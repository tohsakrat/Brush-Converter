import struct
import sys
import os
import numpy as np
from PIL import Image
import io
import math
import re

# ==============================================================================
# 1. 基础工具与核心算法
# ==============================================================================

def create_corpse_image(raw_bytes, label):
    """[Algorithm] 验尸工具"""
    size = len(raw_bytes)
    if size == 0: return None
    side = int(math.ceil(math.sqrt(size)))
    padded = raw_bytes + b'\x00' * (side * side - size)
    try:
        arr = np.frombuffer(padded, dtype='>u1').reshape((side, side))
        print(f"    [Corpse] Generated raw dump image for {label} ({side}x{side})")
        return arr
    except:
        return None

def decode_packbits_row(row_data, target_row_buf, width):
    """[Algorithm] 基础 PackBits 解码"""
    ptr = 0
    col = 0
    row_len = len(row_data)
    target_len = len(target_row_buf)
    
    while ptr < row_len and col < width:
        n = row_data[ptr]
        ptr += 1
        if n < 128: # Literal
            count = n + 1
            write_len = min(count, width - col)
            if ptr + write_len > row_len: write_len = row_len - ptr
            if col + write_len > target_len: write_len = target_len - col
            if write_len > 0:
                target_row_buf[col : col + write_len] = np.frombuffer(row_data[ptr : ptr + write_len], dtype='>u1')
            ptr += count
            col += count
        elif n > 128: # Repeat
            count = 257 - n
            if ptr < row_len:
                val = row_data[ptr]
                ptr += 1
                write_len = min(count, width - col)
                if col + write_len > target_len: write_len = target_len - col
                if write_len > 0:
                    target_row_buf[col : col + write_len] = val
                col += count
    return col

def parse_intermediate_header(data, ch_idx):
    """[Helper] 解析并打印通道间的中间头"""
    if len(data) < 31: 
        print(f"        [Serial] Ch{ch_idx} Header (Short): {data.hex()}")
        return

    try:
        # [Ver 4][Len 4][Unk 4][Top 4][Left 4][Bot 4][Right 4][Depth 2][Comp 1]
        ver, length, unk, top, left, bottom, right, depth, comp = struct.unpack('>IIIIIIIHB', data[:31])
        print(f"        [Serial] Ch{ch_idx} Intermediate Header :: Ver:{ver} Len:{length} Unk:{unk} Rect:({left},{top},{right},{bottom}) Depth:{depth} Comp:{comp}")
    except Exception as e:
        print(f"        [Serial] Ch{ch_idx} Header Parse Err: {e} Raw: {data.hex()}")

def rle_decode(data_bytes, h, w, channels, strict=True, debug_tag=""):
    """[Algorithm] 标准 RLE 解码器 (Interleaved Mode)"""
    header_count = h * channels
    table_size = header_count * 2
    
    if len(data_bytes) < table_size: return None, 0

    if not strict and debug_tag:
        probe = data_bytes[:64].hex()
        print(f"        [Probe {debug_tag}] Header+Data: {probe} ...")

    try:
        line_byte_counts = np.frombuffer(data_bytes[:table_size], dtype='>u2')
    except: return None, 0
    
    if strict:
        total_calc = np.sum(line_byte_counts)
        if total_calc > len(data_bytes) * 2: return None, 0
    
    offset = table_size
    planes = []
    max_offset = offset
    
    for c in range(channels):
        img_mat = np.zeros((h, w), dtype='>u1')
        plane_broken = False
        try:
            for i in range(h):
                idx = c * h + i
                if idx >= len(line_byte_counts): break
                byte_cnt = line_byte_counts[idx]
                if byte_cnt == 0: continue
                
                end_pos = offset + byte_cnt
                
                if end_pos > len(data_bytes):
                    if strict: raise ValueError(f"Truncated")
                    else:
                        valid = len(data_bytes) - offset
                        if valid > 0: decode_packbits_row(data_bytes[offset:], img_mat[i], w)
                        offset = len(data_bytes)
                        max_offset = offset
                        plane_broken = True
                        break 
                
                row_slice = data_bytes[offset : end_pos]
                offset += byte_cnt
                max_offset = max(max_offset, offset)
                decode_packbits_row(row_slice, img_mat[i], w)
            planes.append(img_mat)
        except Exception:
            if strict: return None, 0
            planes.append(img_mat)
            break

    if not planes: return None, 0
    
    res = None
    if strict:
        if len(planes) != channels: return None, 0
        if channels == 1: res = planes[0]
        else: res = np.dstack(planes)
    else:
        while len(planes) < channels: planes.append(np.zeros((h, w), dtype='>u1'))
        if channels == 1: res = planes[0]
        else: res = np.dstack(planes[:channels])
    
    return res, max_offset

def rle_decode_serial(data_bytes, h, w, channels, strict=True):
    """
    [Algorithm] 串行 RLE 解码器 (Serial Mode)
    智能特性：自动跳过并打印每个通道之间的重复 Header
    """
    offset = 0
    planes = []
    
    for c in range(channels):
        if offset >= len(data_bytes): 
            if strict: return None, 0
            planes.append(np.zeros((h, w), dtype='>u1'))
            continue
            
        current_stream = data_bytes[offset:]
        
        # [Smart Skip & Print] 探测并解析中间的 Header
        header_skip = 0
        if c > 0 or not strict:
            search_limit = min(len(current_stream), 200)
            peek_header = current_stream[:search_limit]
            
            # 查找 Depth(8)+Compression(1) 标记
            sig_idx = peek_header.find(b'\x00\x08\x01')
            if sig_idx != -1:
                potential_skip = sig_idx + 3
                if potential_skip > 10:
                    parse_intermediate_header(current_stream[:potential_skip], c)
                    header_skip = potential_skip
                    current_stream = data_bytes[offset + header_skip:]

        debug_tag = f"Serial_Ch{c}" if not strict else ""
        plane, consumed = rle_decode(current_stream, h, w, 1, strict=strict, debug_tag=debug_tag)
        
        if plane is None:
            if strict: return None, 0
            planes.append(np.zeros((h, w), dtype='>u1'))
            offset = len(data_bytes) 
        else:
            planes.append(plane)
            total_consumed = header_skip + consumed
            offset += total_consumed
            
            if not strict:
                print(f"        [Serial] Ch{c} decoded. Consumed: {total_consumed} (Header: {header_skip}, Data: {consumed})")
        
    if not planes: return None, 0
    
    if strict and len(planes) != channels: return None, 0
    
    while len(planes) < channels: planes.append(np.zeros((h, w), dtype='>u1'))
    
    if channels == 1: res = planes[0]
    else: res = np.dstack(planes[:channels])
    
    return res, offset

def raw_decode(data, h, w, channels):
    """[Algorithm] 通用 RAW 解码"""
    plane_size = h * w
    planes = []
    ptr = 0
    for c in range(channels):
        if c > 0 and ptr + 128 < len(data):
            peek = data[ptr : ptr+128]
            vidx = peek.find(struct.pack('>IIH', h, w, 8))
            if vidx != -1: ptr += vidx + 11

        if ptr + plane_size <= len(data):
            planes.append(np.frombuffer(data[ptr : ptr+plane_size], dtype='>u1').reshape((h, w)))
            ptr += plane_size
        else:
            planes.append(np.zeros((h, w), dtype='>u1'))
            
    if not planes: return None, 0
    res = None
    if len(planes) == 1: res = planes[0]
    elif len(planes) == channels: res = np.dstack(planes)
    else: res = planes[0]
    return res, ptr

# ==============================================================================
# 2. 详细流式读取器
# ==============================================================================

class DetailedStreamReader:
    def __init__(self, data):
        self.data = data
        self.cursor = 0
        self.length = len(data)
        self.indent_level = 0
        self.indent_str = "    "

    def indent(self): self.indent_level += 1
    def dedent(self): 
        if self.indent_level > 0: self.indent_level -= 1
    def is_eof(self): return self.cursor >= self.length
    def tell(self): return self.cursor

    def _log(self, size, name, value_repr, is_skip=False):
        prefix = self.indent_str * self.indent_level
        print(f"[0x{self.cursor-size:08X}] {prefix}{name:<20} : {value_repr}")

    def _log_nonzero(self, start_offset, first_nz_rel, last_nz_rel, nz_data):
        prefix = self.indent_str * (self.indent_level + 1)
        abs_start = start_offset + first_nz_rel
        abs_end = start_offset + last_nz_rel
        hex_dump = nz_data.hex()
        print(f"{prefix}>>> Non-Zero Region: 0x{abs_start:08X} - 0x{abs_end:08X} (Len: {len(nz_data)})")
        print(f"{prefix}>>> Content (Hex): {hex_dump}")
        
        # 尝试 ASCII 解码并打印
        try:
            ascii_dump = nz_data.decode('ascii', errors='ignore')
            clean_ascii = "".join([c if c.isprintable() else '.' for c in ascii_dump])
            print(f"{prefix}>>> Content (ASCII): {clean_ascii}")
        except:
            pass
            
    def _dump_hex_ascii(self, offset, raw_bytes):
        """格式化打印十六进制和 ASCII 对照"""
        prefix = self.indent_str * (self.indent_level + 1)
        chunk_size = 16
        
        print(f"{prefix}>>> Full Hex/ASCII Dump (Size: {len(raw_bytes)})")
        print(f"{prefix}--------------------------------------------------------------------------------------------------------------------")
        
        for i in range(0, len(raw_bytes), chunk_size):
            chunk = raw_bytes[i:i + chunk_size]
            hex_part = ' '.join([f'{b:02x}' for b in chunk]).ljust(chunk_size * 3)
            
            ascii_part = ""
            for b in chunk:
                if 32 <= b <= 126:
                    ascii_part += chr(b)
                else:
                    ascii_part += '.'
            
            print(f"{prefix}0x{offset + i:08X} | {hex_part} | {ascii_part}")
        
        print(f"{prefix}--------------------------------------------------------------------------------------------------------------------")


    def read_u1(self, name="Uint8"):
        if self.cursor + 1 > self.length: raise ValueError("EOF")
        val = self.data[self.cursor]
        self.cursor += 1
        self._log(1, name, f"{val} (0x{val:02X})")
        return val

    def read_u2(self, name="Uint16"):
        if self.cursor + 2 > self.length: raise ValueError("EOF")
        val = struct.unpack('>H', self.data[self.cursor:self.cursor+2])[0]
        self.cursor += 2
        self._log(2, name, f"{val}")
        return val

    def read_u4(self, name="Uint32"):
        if self.cursor + 4 > self.length: raise ValueError("EOF")
        val = struct.unpack('>I', self.data[self.cursor:self.cursor+4])[0]
        self.cursor += 4
        self._log(4, name, f"{val}")
        return val

    def read_str(self, length, name="String"):
        if self.cursor + length > self.length: raise ValueError("EOF")
        raw = self.data[self.cursor:self.cursor+length]
        self.cursor += length
        try: val = raw.decode('ascii', errors='ignore').strip('\x00')
        except: val = "<binary>"
        self._log(length, name, f"'{val}'")
        return val, raw

    def read_utf16(self, length, name="UTF16String"):
        if self.cursor + length > self.length: raise ValueError("EOF")
        raw = self.data[self.cursor:self.cursor+length]
        self.cursor += length
        try: val = raw.decode('utf-16-be').strip('\x00')
        except: val = "<decode_err>"
        self._log(length, name, f"'{val}'")
        return val

    def read_bytes(self, length, name="Bytes"):
        if self.cursor + length > self.length: length = self.length - self.cursor
        raw = self.data[self.cursor:self.cursor+length]
        self.cursor += length
        disp = raw[:16].hex() 
        if len(raw) > 16: disp += "..."
        self._log(length, name, f"Size:{length} [{disp}]")
        return raw
        
    def read_and_dump_full_bytes(self, length, name="Full Dump"):
        """读取全部字节并以 Hex/ASCII 对照模式打印"""
        if self.cursor + length > self.length: length = self.length - self.cursor
        start_offset = self.cursor
        raw = self.data[self.cursor:self.cursor+length]
        self.cursor += length
        
        self._log(length, name, f"Size:{length} [DUMP START]")
        self._dump_hex_ascii(start_offset, raw)
        return raw

    def skip(self, length, name="Skipped", check_nonzero=True):
        if self.cursor + length > self.length: length = self.length - self.cursor
        start_offset = self.cursor
        skipped_data = self.data[self.cursor : self.cursor + length]
        self.cursor += length
        
        if not check_nonzero:
            self._log(length, name, f"Jump {length} bytes (Ignored)", is_skip=True)
            return

        first_nz = -1
        for i, b in enumerate(skipped_data):
            if b != 0:
                first_nz = i
                break
        
        if first_nz == -1:
            self._log(length, name, f"Jump {length} bytes (All Zeros)", is_skip=True)
        else:
            last_nz = -1
            for i in range(len(skipped_data) - 1, first_nz - 1, -1):
                if skipped_data[i] != 0:
                    last_nz = i
                    break
            nz_region = skipped_data[first_nz : last_nz + 1]
            self._log(length, name, f"Jump {length} bytes [!!! NON-ZERO !!!]", is_skip=True)
            self._log_nonzero(start_offset, first_nz, last_nz, nz_region)

    def peek_bytes(self, length):
        return self.data[self.cursor : self.cursor + length]

    def tell(self):
        return self.cursor

# ==============================================================================
# 3. 顺序解析器
# ==============================================================================

class SequentialAbrParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.items = []
        self.version = (1, 2)

    def parse(self):
        if not os.path.exists(self.filepath): return
        with open(self.filepath, 'rb') as f: full_data = f.read()
        
        print(f"\n{'='*80}\nStart Sequential Parsing: {self.filepath}\n{'='*80}\n")
        reader = DetailedStreamReader(full_data)

        print(">>> File Header")
        reader.indent()
        self.version = (reader.read_u2("Major Ver"), reader.read_u2("Minor Ver"))
        reader.dedent()

        while not reader.is_eof():
            print(f"\n>>> Block Segment (Offset 0x{reader.tell():08X})")
            reader.indent()
            sig_raw = reader.peek_bytes(4)
            if len(sig_raw) < 4: break

            if sig_raw != b'8BIM':
                print(f"    [Info] Non-8BIM signature, treating as padding...")
                reader.skip(1, "Padding")
                reader.dedent()
                continue
            
            reader.read_str(4, "Signature") 
            key, _ = reader.read_str(4, "Block Key") 
            length = reader.read_u4("Block Length") 
            block_end = reader.tell() + length
            
            reader.indent() 
            if key == 'samp': self.parse_samp_block(reader, length)
            elif key == 'patt': self.parse_patt_block(reader, length)
            elif key in ['desc', 'titl', '8BIM']: reader.skip(length, f"Ignored ({key})", check_nonzero=False)
            else: reader.skip(length, f"Unknown ({key})")
            
            rem = block_end - reader.tell()
            if rem > 0: reader.skip(rem, "Block Trailing")
            elif rem < 0: print(f"    [Warn] Block over-read by {-rem} bytes")
            
            reader.dedent() 
            reader.dedent() 

    def parse_samp_block(self, reader, block_len):
        target_end = reader.tell() + block_len
        item_idx = 0
        while reader.tell() < target_end:
            if reader.tell() + 4 > target_end: 
                reader.skip(target_end - reader.tell(), "Block End Padding"); break
            print(f"\n    >>> Samp Item #{item_idx}")
            reader.indent()
            item_len = reader.read_u4("Item Length")
            if item_len == 0: reader.dedent(); continue
            item_end = reader.tell() + item_len
            self.parse_single_samp_item(reader, item_len, item_idx, item_end)
            rem = item_end - reader.tell()
            if rem > 0: reader.skip(rem, "Item Trailing")
            pad = (4 - (item_len % 4)) % 4
            if pad > 0 and reader.tell() + pad <= target_end: reader.skip(pad, "Align Pad")
            reader.dedent(); item_idx += 1

    def parse_single_samp_item(self, reader, length, idx, item_end_offset):
        skip_amt = 301 if self.version[1] != 1 else 47
        if skip_amt > length: reader.skip(length, "Data Short"); return
        
        header_bytes = reader.read_bytes(skip_amt, "Fixed Header")
        uuid = f"brush_{idx}"
        try:
            match = re.search(b'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', header_bytes)
            if match: uuid = match.group().decode('ascii')
        except: pass

        top = reader.read_u4("Rect.Top")
        left = reader.read_u4("Rect.Left")
        bottom = reader.read_u4("Rect.Bottom")
        right = reader.read_u4("Rect.Right")
        depth = reader.read_u2("Depth")
        comp = reader.read_u1("Compression") 
        
        h, w = bottom - top, right - left
        rem_len = item_end_offset - reader.tell()
        if rem_len <= 0: return
        
        payload = reader.peek_bytes(rem_len)
        img = None
        consumed = 0
        try:
            if comp == 0: img, consumed = raw_decode(payload, h, w, 1)
            elif comp == 1: img, consumed = rle_decode(payload, h, w, 1, strict=False)
        except: pass

        if consumed > 0 and img is not None:
            reader.read_bytes(consumed, "Image Data")
            self.items.append({'uuid': uuid, 'pix': img, 'type': 'brush'})
        else:
            reader.skip(rem_len, "Decode Failed")

    def parse_patt_block(self, reader, block_len):
        target_end = reader.tell() + block_len
        item_idx = 0
        while reader.tell() < target_end:
            if reader.tell() + 4 > target_end: 
                reader.skip(target_end - reader.tell(), "Block End Padding"); break
            print(f"\n    >>> Patt Item #{item_idx}")
            reader.indent()
            item_len = reader.read_u4("Item Length")
            if item_len == 0: reader.dedent(); continue
            item_end = reader.tell() + item_len
            # Pass item_end to restrict parsing
            self.parse_single_patt_item(reader, item_len, item_idx, item_end)
            rem = item_end - reader.tell()
            if rem > 0: self.parse_patt_trailing_data(reader, rem, item_end) # Structured trailing data parsing
            pad = (4 - (item_len % 4)) % 4
            if pad > 0 and reader.tell() + pad <= target_end: reader.skip(pad, "Align Pad")
            reader.dedent(); item_idx += 1

    def parse_patt_trailing_data(self, reader, length, item_end_offset):
        """解析 Pattern 图像数据后的尾部元数据，这部分数据似乎不是必要的，如果要进行打包，则完全忽略这部分"""
        print(f"    --- Item Trailing Metadata ({length} bytes) ---")
        reader.indent()
        
        # 边界定义 (基于 1319 bytes 块的分析)
        TRAIL_PADDING = 91 
        VECTOR_HEADER_LEN = 12
        
        # 1. 跳过初始 Padding (91 bytes of Zeros)
        if length > TRAIL_PADDING:
            reader.skip(TRAIL_PADDING, "Initial Padding (Zeros)")
            
            # 2. 解析 Vector Data Block
            remaining_to_read = item_end_offset - reader.tell()
            
            if remaining_to_read >= VECTOR_HEADER_LEN:
                print(f"    --- Vector Path Block ({remaining_to_read} bytes) ---")
                reader.indent()
                
                # 2a. Vector Block Header (12 bytes)
                v_key = reader.read_u4("VKey") # (ID)
                v_len = reader.read_u4("VLen") # (Length)
                v_unk = reader.read_u4("VUnk") # (Version/Unknown)
                
                # 2b. Vector Data / Compressed Shape Info (Remaining)
                data_len = remaining_to_read - 12
                if data_len > 0:
                    # 使用新的 dump 函数进行完整打印
                    reader.read_and_dump_full_bytes(data_len, "Vector Shape Data (Compressed)")
                    
                reader.dedent()
                print(f"    --- Vector Path Block End ---")
        
        # 3. 剩余数据 (通常是 0 或少量未知数据)
        remaining = item_end_offset - reader.tell()
        if remaining > 0:
            reader.skip(remaining, "Final Trailing Data")
        
        reader.dedent()
        print(f"    --- Trailing End ---")


    def parse_single_patt_item(self, reader, length, idx, item_end_offset):
        ver = reader.read_u4("Ver")
        mode = reader.read_u4("Mode")
        h_outer = reader.read_u2("H")
        w_outer = reader.read_u2("W")
        name_len = reader.read_u4("NameLen")
        patt_name = reader.read_utf16(name_len * 2, "Name")
        id_len = reader.read_u1("IDLen")
        uuid = f"patt_{idx}"
        if id_len > 0: uuid, _ = reader.read_str(id_len, "ID")
        if mode == 2: reader.read_bytes(768, "Index Table")

        search_lim = item_end_offset - reader.tell()
        if search_lim <= 0: return

        peek_area = reader.peek_bytes(search_lim)
        sig = struct.pack('>IIII', 0, 0, h_outer, w_outer) 
        sig_pos = peek_area.find(sig)
        
        if sig_pos == -1:
            reader.skip(search_lim, "Sig Not Found")
            corpse = create_corpse_image(peek_area, f"{uuid}_NoSig")
            if corpse is not None: self.items.append({'uuid': uuid + "_CORPSE", 'pix': corpse})
            return
        
        gap = sig_pos - 8
        if gap > 0: reader.read_bytes(gap, "Gap Pad")
        
        print(f"    --- Inner Header ---")
        reader.indent()
        reader.read_u4("InVer"); reader.read_u4("InLen")
        reader.read_u4("InTop"); reader.read_u4("InLeft"); reader.read_u4("InBot"); reader.read_u4("InRight")
        reader.read_u4("MaxD"); reader.read_u4("Unk"); reader.read_u4("CompSz"); reader.read_u4("BitD")
        reader.read_u4("ActTop"); reader.read_u4("ActLeft"); reader.read_u4("ActBot"); reader.read_u4("ActRight")
        reader.read_u2("D2"); 
        comp_mode = reader.read_u1("CompMode")
        reader.dedent()
        print(f"    --------------------")
        
        h, w = h_outer, w_outer
        channels = 3
        if mode == 1: channels = 1
        elif mode == 2: channels = 1
        elif mode == 4: channels = 4
        
        rem_payload = item_end_offset - reader.tell()
        preview = reader.peek_bytes(rem_payload) 
        
        img = None
        consumed = 0
        method = "None"

        try:
            if comp_mode == 1: # RLE
                img, consumed = rle_decode(preview, h, w, channels, strict=True)
                method = "Strict(Interleaved)"
                
                if img is None:
                    img, consumed = rle_decode_serial(preview, h, w, channels, strict=True)
                    method = "Strict(Serial)"

                if img is None and channels == 3:
                    img, consumed = rle_decode(preview, h, w, 4, strict=True)
                    if img is None: 
                        img, consumed = rle_decode_serial(preview, h, w, 4, strict=True)
                    method = "Retry4ch"

                if img is None:
                    print(f"    [Warn] All strict modes failed. Engaging FORCE MODE...")
                    img, consumed = rle_decode_serial(preview, h, w, channels, strict=False)
                    method = "FORCE(Serial)"
                    
                    if img is None:
                        print(f"    [Force] Serial failed. Trying FORCE INTERLEAVED...")
                        img, consumed = rle_decode(preview, h, w, channels, strict=False)
                        method = "FORCE(Interleaved)"
                
                if img is None and channels != 1:
                    print(f"    [Warn] Force failed. Fallback to 1-channel decode...")
                    img, consumed = rle_decode(preview, h, w, 1, strict=True)
                    method = "Fallback1ch"

            else: # RAW
                img, consumed = raw_decode(preview, h, w, channels)
                method = "RAW"
        except: pass

        if img is not None and consumed > 0:
            print(f"    [Info] Decoded via {method}")
            reader.read_bytes(consumed, "Image Data")
            self.items.append({'uuid': uuid, 'pix': img, 'type': 'pattern'})
        else:
            print("    [Fatal] Decoding failed.")
            corpse = create_corpse_image(preview[:50000], f"{uuid}_Fail")
            if corpse is not None: self.items.append({'uuid': uuid + "_FAIL", 'pix': corpse})
            reader.skip(rem_payload, "Payload Skipped")

    def save_images(self, out_dir="final_output"):
        if not os.path.exists(out_dir): os.makedirs(out_dir)
        print(f"\n{'='*80}\nSaving {len(self.items)} items...\n{'='*80}")
        for i, item in enumerate(self.items):
            arr = item['pix']
            if arr is None: continue
            safe_uuid = re.sub(r'[\\/*?:"<>|]', "_", str(item['uuid']))
            fname = os.path.join(out_dir, f"{safe_uuid}.png")
            if os.path.exists(fname): fname = os.path.join(out_dir, f"{safe_uuid}_{i}.png")
            try:
                img = None
                if arr.ndim == 2: img = Image.fromarray(arr, 'L')
                elif arr.ndim == 3:
                    if arr.shape[2] == 1: img = Image.fromarray(arr[:,:,0], 'L')
                    elif arr.shape[2] == 3: img = Image.fromarray(arr, 'RGB')
                    elif arr.shape[2] == 4: img = Image.fromarray(arr, 'RGBA').convert('RGB')
                if item.get('type') == 'brush' and img and img.mode != 'L': img = img.convert('L')
                if img: img.save(fname)
            except Exception as e: print(f"[Err] Saving {fname}: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        p = SequentialAbrParser(sys.argv[1])
        p.parse()
        p.save_images()
