import struct
import sys
import os
import numpy as np
from PIL import Image
import io
import math
import re
import json

# ==============================================================================
# 1. 基础工具与核心算法 (Base Tools & Algorithms)
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
        # print(f"        [Probe {debug_tag}] Header+Data: {probe} ...")

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
# 2. 详细流式读取器 (DetailedStreamReader) - 增强版
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
        print(f"[0x{self.cursor-size:08X}] {prefix}{name:<25} : {value_repr}")

    def _print_hex_chunk(self, offset, raw_bytes, prefix):
        """Standard Hex Printer (16 bytes per line)"""
        chunk_size = 16
        for i in range(0, len(raw_bytes), chunk_size):
            chunk = raw_bytes[i:i + chunk_size]
            hex_part = ' '.join([f'{b:02x}' for b in chunk]).ljust(chunk_size * 3)
            ascii_part = ""
            for b in chunk:
                if 32 <= b <= 126: ascii_part += chr(b)
                else: ascii_part += '.'
            print(f"{prefix}0x{offset + i:08X} | {hex_part} | {ascii_part}")

    def _dump_hex_smart_internal(self, offset, raw_bytes, prefix):
        """
        [UNIFIED DEBUG INTERFACE]
        核心逻辑：若 > 128 字节，只打印 头64 + ... + 尾64
        """
        size = len(raw_bytes)
        if size <= 128:
            self._print_hex_chunk(offset, raw_bytes, prefix)
        else:
            # Head 64
            self._print_hex_chunk(offset, raw_bytes[:64], prefix)
            
            # Ellipsis
            print(f"{prefix}..." + " " * 30 + f"[ Skipped {size - 128} bytes ]" + " " * 5 + "...")
            
            # Tail 64
            self._print_hex_chunk(offset + size - 64, raw_bytes[-64:], prefix)

    def read_and_dump_full_bytes(self, length, name="Full Dump"):
        """
        [MODIFIED] 现在所有调用此函数的地方都会自动应用 128 字节截断逻辑
        """
        if self.cursor + length > self.length: length = self.length - self.cursor
        start_offset = self.cursor
        raw = self.data[self.cursor:self.cursor+length]
        self.cursor += length
        
        prefix = self.indent_str * (self.indent_level + 1)
        print(f"{prefix}>>> Dump: {name} (Size: {length})")
        print(f"{prefix}{'-'*80}")
        self._dump_hex_smart_internal(start_offset, raw, prefix)
        print(f"{prefix}{'-'*80}")
        return raw

    def dump_section_smart(self, start_offset, end_offset, label="Context"):
        """
        [UNIFIED] 用于打印指定区间的智能 Dump
        """
        if start_offset < 0: start_offset = 0
        if end_offset > self.length: end_offset = self.length
        
        size = end_offset - start_offset
        prefix = self.indent_str * (self.indent_level + 1)
        
        print(f"{prefix}>>> Smart Dump: {label} (Range: 0x{start_offset:08X}-0x{end_offset:08X}, Size: {size})")
        print(f"{prefix}{'='*80}")
        
        if size <= 0:
            print(f"{prefix}[Empty Section]")
        else:
            raw = self.data[start_offset:end_offset]
            self._dump_hex_smart_internal(start_offset, raw, prefix)
            
        print(f"{prefix}{'='*80}")

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
    
    def read_u8(self, name="Uint64"):
        if self.cursor + 8 > self.length: raise ValueError("EOF")
        val = struct.unpack('>Q', self.data[self.cursor:self.cursor+8])[0]
        self.cursor += 8
        self._log(8, name, f"{val}")
        return val
    
    def read_double(self, name="Double"):
        if self.cursor + 8 > self.length: raise ValueError("EOF")
        val = struct.unpack('>d', self.data[self.cursor:self.cursor+8])[0]
        self.cursor += 8
        self._log(8, name, f"{val:.6f}")
        return val

    def read_str(self, length, name="String"):
        if self.cursor + length > self.length: raise ValueError("EOF")
        raw = self.data[self.cursor:self.cursor+length]
        self.cursor += length
        try: val = raw.decode('ascii', errors='ignore').strip('\x00')
        except: val = "<binary>"
        self._log(length, name, f"'{val}'")
        return val, raw
    
    def read_pstring(self, name="PString"):
        if self.cursor + 4 > self.length: raise ValueError("EOF")
        length = struct.unpack('>I', self.data[self.cursor:self.cursor+4])[0]
        self.cursor += 4
        self._log(4, name + ".Len", f"{length}")
        if length == 0: return ""
        if self.cursor + length > self.length: raise ValueError("EOF PString content")
        raw = self.data[self.cursor:self.cursor+length]
        self.cursor += length
        try: val = raw.decode('utf-16-be')
        except: val = raw.decode('latin1', errors='replace')
        self._log(length, name + ".Val", f"'{val}'")
        return val

    def read_unicode_string(self, name="UnicodeString"):
        if self.cursor + 4 > self.length: raise ValueError("EOF")
        char_len = struct.unpack('>I', self.data[self.cursor:self.cursor+4])[0]
        self.cursor += 4
        self._log(4, name + ".CharLen", f"{char_len} (Exp Bytes: {char_len*2})")
        if char_len == 0: return ""
        byte_len = char_len * 2
        if self.cursor + byte_len > self.length: raise ValueError("EOF Unicode content")
        raw = self.data[self.cursor:self.cursor+byte_len]
        self.cursor += byte_len
        try: val = raw.decode('utf-16-be').strip('\x00')
        except: val = "<decode_err>"
        self._log(byte_len, name + ".Val", f"'{val}'")
        return val

    def read_ostype(self, name="OSType"):
        if self.cursor + 4 > self.length: raise ValueError("EOF")
        raw = self.data[self.cursor:self.cursor+4]
        self.cursor += 4
        try: 
            s_val = raw.decode('ascii')
            if all(32 <= c <= 126 for c in raw):
                 self._log(4, name, f"'{s_val}'")
                 return s_val
        except: pass
        self._log(4, name, f"Hex:{raw.hex()}")
        return raw

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
        
        # [ADDED] ASCII Representation for Byte Reads
        ascii_repr = ""
        limit = min(len(raw), 32)
        for b in raw[:limit]:
            if 32 <= b <= 126: ascii_repr += chr(b)
            else: ascii_repr += "."
        if len(raw) > limit: ascii_repr += "..."
        
        self._log(length, name, f"Size:{length} [{disp}] '{ascii_repr}'")
        return raw

    def skip(self, length, name="Skipped", check_nonzero=True):
        if self.cursor + length > self.length: length = self.length - self.cursor
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
            self._log(length, name, f"Jump {length} bytes [!!! NON-ZERO !!!]", is_skip=True)

    def peek_bytes(self, length):
        return self.data[self.cursor : self.cursor + length]
    
    def peek_u4(self):
        if self.cursor + 4 > self.length: return 0
        return struct.unpack('>I', self.data[self.cursor:self.cursor+4])[0]

# ==============================================================================
# 3. Action Descriptor Parser (Debug Enhanced & Table Driven & JSON Build)
# ==============================================================================

class ActionDescriptorParser:
    # [TABLE 1] Known Key Modes (For Key Length)
    # STANDARD: 4-byte length (or implicit Code)
    # COMPACT: 1-byte length
    KNOWN_KEY_MODES = {
        'Brsh': 'STANDARD', 'Nm  ': 'STANDARD', 'Nm': 'STANDARD', 'Dmtr': 'STANDARD',
        'Hrdn': 'STANDARD', 'Angl': 'STANDARD', 'Rndn': 'STANDARD', 'Spcn': 'STANDARD',
        'Intr': 'STANDARD', 'szVr': 'STANDARD', 'bVTy': 'STANDARD', 'fStp': 'STANDARD',
        'jitter': 'STANDARD', 'angleDynamics': 'STANDARD', 'roundnessDynamics': 'STANDARD',
        'grad': 'STANDARD', 'inpt': 'STANDARD', 'midp': 'STANDARD', 'Cl  ': 'STANDARD',
        'Ofst': 'STANDARD', 'Type': 'STANDARD', 'Loc ': 'STANDARD', 'Mdpn': 'STANDARD',
        
        'flipX': 'COMPACT', 'flipY': 'COMPACT', 'useTipDynamics': 'COMPACT',
        'minimumDiameter': 'COMPACT', 'minimumRoundness': 'COMPACT', 'tiltScale': 'COMPACT',
        'useScatter': 'COMPACT', 'dualBrush': 'COMPACT', 'brushGroup': 'COMPACT',
        'useBrushGroup': 'COMPACT', 'useTexture': 'COMPACT', 'usePaintDynamics': 'COMPACT',
        'useColorDynamics': 'COMPACT', 'Wtdg': 'COMPACT', 'Nose': 'COMPACT', 'Rpt ': 'COMPACT',
        'Rpt': 'COMPACT', 'computedBrush': 'COMPACT'
    }

    # [TABLE 2] Known Object Name Modes (For 'Objc' type Name Length)
    # STANDARD: 4-byte length prefix (Usually 00 00 00 00 for empty)
    # COMPACT: 2-byte length prefix (Usually 00 00 for empty)
    KNOWN_OBJ_NAME_MODES = {
        'Brsh': 'COMPACT', 
        'szVr': 'COMPACT', 
        'angleDynamics': 'COMPACT',
        'roundnessDynamics': 'COMPACT', 
        'dualBrush': 'COMPACT', 
        'brushGroup': 'COMPACT'
    }

    # [TABLE 3] Known ClassID Padding Modes (For Descriptor Parsing)
    # STANDARD: Pad to 4 bytes
    # COMPACT: No Padding (tightly packed)
    KNOWN_CLASSID_MODES = {
        'brushPreset': 'COMPACT',
        'computedBrush': 'COMPACT',
        'null': 'COMPACT' # 'null' is 4 bytes, so padding is 0 anyway, but good to mark
    }

    def __init__(self, reader):
        self.reader = reader
        self.last_item_start = 0
        self.last_item_end = 0
        self.last_item_idx = -1
        self.global_last_success_end = reader.tell()
    
    def parse_descriptor(self, label="Descriptor"):
        self.reader.indent()
        print(f"{self.reader.indent_str * self.reader.indent_level}--- {label} Start ---")
        
        try:
            name_len = self.reader.read_u4("ClassID.Len")
            
            total_classid_bytes = 4
            class_id = ""
            if name_len == 0:
                class_id = self.reader.read_ostype("ClassID.Code")
                total_classid_bytes += 4
            else:
                class_id_bytes = self.reader.read_bytes(name_len, "ClassID.StrBytes")
                try: class_id = class_id_bytes.decode('utf-8')
                except: class_id = class_id_bytes.hex()
                total_classid_bytes += name_len
                print(f"{self.reader.indent_str * self.reader.indent_level}ClassID: '{class_id}'")

            padding = (4 - (total_classid_bytes % 4)) % 4
            
            if padding > 0:
                # [Strategy] Check Table first, then Heuristic
                skip_needed = True
                
                # 1. Table Check
                if class_id in self.KNOWN_CLASSID_MODES:
                    if self.KNOWN_CLASSID_MODES[class_id] == 'COMPACT':
                        print(f"{self.reader.indent_str * self.reader.indent_level}[Table] ClassID '{class_id}' is COMPACT. Skipping Padding.")
                        skip_needed = False
                else:
                    # 2. Heuristic Check (Fallback)
                    safe_pos = self.reader.tell()
                    self.reader.cursor += padding
                    val_padded = -1
                    if self.reader.cursor + 4 <= self.reader.length:
                        raw = self.reader.peek_bytes(4)
                        val_padded = struct.unpack('>I', raw)[0]
                    self.reader.cursor = safe_pos
                    
                    val_raw = -1
                    if self.reader.cursor + 4 <= self.reader.length:
                        raw = self.reader.peek_bytes(4)
                        val_raw = struct.unpack('>I', raw)[0]
                        
                    # [Threshold] Lowered to 256 to catch small but wrong values (e.g. 3584 vs 14)
                    is_suspicious_padded = val_padded > 256
                    is_sane_raw = val_raw < 256
                    
                    if (is_suspicious_padded and is_sane_raw) or (val_padded > 100000 and val_raw < 100000):
                        print(f"{self.reader.indent_str * self.reader.indent_level}[Heuristic] ClassID Padding Skipped! (Padded NumItems: {val_padded} vs Raw: {val_raw})")
                        skip_needed = False

                if skip_needed:
                    self.reader.skip(padding, "ClassID.Pad")

            peek = self.reader.peek_bytes(8)
            is_short_count = False
            
            if len(peek) >= 8:
                val_u4 = struct.unpack('>I', peek[:4])[0]
                val_u2 = struct.unpack('>H', peek[:2])[0]
                
                if peek[0:6] == b'\x00\x00\x00\x00\x00\x00':
                    print(f"{self.reader.indent_str * self.reader.indent_level}[Heuristic] Short NumItems (Zero) Detected.")
                    is_short_count = True
                elif val_u4 > 5000 and val_u2 < 5000:
                    peek_key_len = struct.unpack('>I', peek[2:6])[0]
                    if peek_key_len < 256:
                        print(f"{self.reader.indent_str * self.reader.indent_level}[Heuristic] Short NumItems Detected! (u4={val_u4} vs u2={val_u2}, Next KeyLen={peek_key_len})")
                        is_short_count = True
            
            body_data = {}
            if is_short_count:
                body_data = self.parse_descriptor_body_short_count(label)
            else:
                body_data = self.parse_descriptor_body(label)
            
            return {'classID': class_id, 'items': body_data}
                
        except Exception as e:
            print(f"{self.reader.indent_str * self.reader.indent_level}[Err] Descriptor Parse Failed: {e}")
            self.reader.read_and_dump_full_bytes(64, "Error Context")
            raise e
        finally:
            self.reader.dedent()

    def parse_descriptor_body(self, label="DescriptorBody"):
        num_items = self.reader.read_u4("NumItems")
        self.last_item_start = self.reader.tell()
        self.last_item_end = self.reader.tell()
        self.last_item_idx = -1
        
        items = {}

        for i in range(num_items):
            this_item_start = self.reader.tell()
            try:
                key, val = self.parse_item(i)
                items[key] = val
                self.last_item_idx = i
                self.last_item_start = this_item_start
                self.last_item_end = self.reader.tell()
                self.global_last_success_end = self.reader.tell()
            except Exception as e:
                print(f"{self.reader.indent_str * self.reader.indent_level}[Err] Item #{i} Failed: {e}")
                print(f"\n{self.reader.indent_str * self.reader.indent_level}!!! GLOBAL CONTEXT (Last Success -> Current Crash) !!!")
                context_start = max(0, self.global_last_success_end - 64)
                self.reader.dump_section_smart(context_start, self.global_last_success_end, "Last Successful Item End")
                if this_item_start > self.global_last_success_end:
                     self.reader.dump_section_smart(self.global_last_success_end, this_item_start, "Gap / Header / Parent Context")
                consumed = self.reader.tell() - this_item_start
                if consumed > 0:
                    print(f"\n{self.reader.indent_str * self.reader.indent_level}!!! PROBLEM ITEM (#{i}) - PARTIAL READ !!!")
                    self.reader.dump_section_smart(this_item_start, self.reader.tell(), f"Item #{i} Partial")
                print(f"\n{self.reader.indent_str * self.reader.indent_level}!!! FUTURE BYTES !!!")
                self.reader.read_and_dump_full_bytes(64, "Future Context")
                raise e
        print(f"{self.reader.indent_str * self.reader.indent_level}--- {label} End ---")
        return items

    def parse_descriptor_body_short_count(self, label="DescriptorBody(Short)"):
        num_items = self.reader.read_u2("NumItems(Short)")
        self.last_item_start = self.reader.tell()
        self.last_item_end = self.reader.tell()
        self.last_item_idx = -1
        items = {}
        
        for i in range(num_items):
            this_item_start = self.reader.tell()
            try:
                key, val = self.parse_item(i)
                items[key] = val
                self.last_item_idx = i
                self.last_item_start = this_item_start
                self.last_item_end = self.reader.tell()
                self.global_last_success_end = self.reader.tell()
            except Exception as e:
                print(f"{self.reader.indent_str * self.reader.indent_level}[Err] Item #{i} Failed: {e}")
                print(f"\n{self.reader.indent_str * self.reader.indent_level}!!! GLOBAL CONTEXT !!!")
                context_start = max(0, self.global_last_success_end - 64)
                self.reader.dump_section_smart(context_start, self.global_last_success_end, "Last Successful Item End")
                if this_item_start > self.global_last_success_end:
                     self.reader.dump_section_smart(self.global_last_success_end, this_item_start, "Gap / Header")
                consumed = self.reader.tell() - this_item_start
                if consumed > 0:
                    print(f"\n{self.reader.indent_str * self.reader.indent_level}!!! PROBLEM ITEM (#{i}) - PARTIAL READ !!!")
                    self.reader.dump_section_smart(this_item_start, self.reader.tell(), f"Item #{i} Partial")
                print(f"\n{self.reader.indent_str * self.reader.indent_level}!!! FUTURE BYTES !!!")
                self.reader.read_and_dump_full_bytes(64, "Future Context")
                raise e
        print(f"{self.reader.indent_str * self.reader.indent_level}--- {label} End ---")
        return items

    def _read_smart_key_length(self, label="Key"):
        """
        [Modified] Table-Driven Key Length Detection
        Prioritizes known keys in KNOWN_KEY_MODES.
        """
        peek = self.reader.peek_bytes(5)
        if len(peek) < 5: return self.reader.read_u4(f"{label}.Len"), False

        # 1. Check Compact (1-byte length) vs Table
        compact_len = peek[0]
        if 0 < compact_len < 100: # Reasonable compact length
            try:
                candidate_str = self.reader.data[self.reader.cursor + 1 : self.reader.cursor + 1 + compact_len].decode('ascii')
                if candidate_str in self.KNOWN_KEY_MODES and self.KNOWN_KEY_MODES[candidate_str] == 'COMPACT':
                    print(f"{self.reader.indent_str * self.reader.indent_level}[SmartKey] Table Hit: '{candidate_str}' is COMPACT")
                    self.reader.skip(1, f"{label}.CompactLen")
                    return compact_len, True
            except: pass

        # 2. Check Standard (4-byte length) vs Table
        std_len = struct.unpack('>I', peek[:4])[0]
        if std_len == 0:
            # Length 0 usually means Implicit Key Code (4 bytes)
            try:
                candidate_code = self.reader.data[self.reader.cursor + 4 : self.reader.cursor + 8].decode('ascii')
                if candidate_code in self.KNOWN_KEY_MODES and self.KNOWN_KEY_MODES[candidate_code] == 'STANDARD':
                    print(f"{self.reader.indent_str * self.reader.indent_level}[SmartKey] Table Hit: '{candidate_code}' (Code) is STANDARD")
                    return self.reader.read_u4(f"{label}.Len"), False
            except: pass
        elif std_len < 256:
            try:
                candidate_str = self.reader.data[self.reader.cursor + 4 : self.reader.cursor + 4 + std_len].decode('ascii')
                if candidate_str in self.KNOWN_KEY_MODES and self.KNOWN_KEY_MODES[candidate_str] == 'STANDARD':
                    print(f"{self.reader.indent_str * self.reader.indent_level}[SmartKey] Table Hit: '{candidate_str}' is STANDARD")
                    return self.reader.read_u4(f"{label}.Len"), False
            except: pass

        # 3. Fallback to Heuristics
        val_u4 = std_len
        
        # Case 1: Standard Small 4-byte Length (e.g. 00 00 00 0A)
        if val_u4 < 100000: 
            return self.reader.read_u4(f"{label}.Len"), False 
            
        # Case 2: Compact Length (1 byte)
        first_byte = peek[0]
        
        # Sub-case 2a: Non-zero compact length
        if 0 < first_byte < 128:
            # Implicit Key Code Heuristic
            is_ostype = all(32 <= b <= 126 for b in peek[:4])
            if is_ostype and first_byte > 50: 
                 print(f"{self.reader.indent_str * self.reader.indent_level}[SmartKey] Implicit Key Code Detected (Len=0)! (Peek: {peek[:4].hex()})")
                 return 0, False 

            print(f"{self.reader.indent_str * self.reader.indent_level}[SmartKey] Compact Key Detected! Len: {first_byte} (Peek: {peek[:4].hex()})")
            self.reader.skip(1, f"{label}.CompactLen")
            return first_byte, True 
            
        # Sub-case 2b: Zero compact length (00 + OSType)
        if first_byte == 0 and len(peek) >= 5:
            potential_ostype = peek[1:5]
            if all(32 <= b <= 126 for b in potential_ostype):
                 print(f"{self.reader.indent_str * self.reader.indent_level}[SmartKey] Compact Key (0) + OSType Detected! (Peek: {peek.hex()})")
                 self.reader.skip(1, f"{label}.CompactLen")
                 return 0, True 

        # Fallback
        return self.reader.read_u4(f"{label}.Len"), False

    def parse_item(self, idx):
        # 1. [IMPROVED] Implicit Key Detection Logic
        is_implicit_key = False
        peek_type = self.reader.peek_bytes(8)
        if len(peek_type) >= 8:
            pot_type = peek_type[:4]
            pot_data = peek_type[4:]
            
            if pot_type == b'Objc':
                # If Type is Objc, next should be Flag (0 or 1).
                flag_val = struct.unpack('>I', pot_data)[0]
                if flag_val == 0 or flag_val == 1:
                    print(f"{self.reader.indent_str * self.reader.indent_level}[Heuristic] Implicit Empty Key Detected before 'Objc'.")
                    is_implicit_key = True
                    
        if is_implicit_key:
            key = ""
            key_len = 0
            is_compact = False 
            print(f"{self.reader.indent_str * self.reader.indent_level}[Stats] Key: '' (Implicit) | Mode: IMPLICIT | Len: 0")
        else:
            # 1. Key (Smart Read with Table)
            key_len, is_compact = self._read_smart_key_length("Key")
            
            key = ""
            if key_len == 0:
                key = self.reader.read_ostype("Key.Code")
            else:
                key_bytes = self.reader.read_bytes(key_len, "Key.StrBytes")
                try: key = key_bytes.decode('utf-8')
                except: key = key_bytes.hex()
            
            # Log Stats
            mode_str = "COMPACT" if is_compact else "STANDARD"
            print(f"{self.reader.indent_str * self.reader.indent_level}[Stats] Key: '{key}' | Mode: {mode_str} | Len: {key_len}")
        
        # 2. Type (Implicit Detection)
        peek_type = self.reader.peek_bytes(4)
        is_valid_type = True
        try:
            if not all(32 <= b <= 126 for b in peek_type):
                is_valid_type = False
        except:
            is_valid_type = False
        
        val = None
        if is_valid_type:
            type_code = self.reader.read_ostype("Type")
            val = self.parse_value_by_type(type_code, key)
        else:
            print(f"{self.reader.indent_str * self.reader.indent_level}[Heuristic] Implicit Type 'Objc' Detected for key '{key}'")
            print(f"{self.reader.indent_str * self.reader.indent_level}[Heuristic] Parsing as Headless Descriptor Body")
            val = self.parse_descriptor_body(f"{key}.HeadlessObj")
            
        return key, val

    def parse_value_by_type(self, type_code, label):
        type_str = type_code if isinstance(type_code, str) else type_code.decode('ascii', errors='ignore')
        
        print(f"{self.reader.indent_str * self.reader.indent_level}Type: '{type_str}'")

        if type_str == 'TEXT':
            val = self.reader.read_unicode_string(f"{label}.Val(Text)")
            return val
        elif type_str == 'UntF': 
            unit = self.reader.read_ostype(f"{label}.Unit")
            val = self.reader.read_double(f"{label}.Val(Double)")
            return {'type': 'UntF', 'unit': unit, 'value': val}
        elif type_str == 'doub': 
            val = self.reader.read_double(f"{label}.Val(Double)")
            return val
        elif type_str == 'long':
            val = self.reader.read_u4(f"{label}.Val(Long)")
            return val
        elif type_str == 'bool':
            # [FIXED] Read bool byte.
            val_bool = self.reader.read_u1(f"{label}.Val(Bool)")
            
            peek_pad = self.reader.peek_bytes(3)
            if peek_pad == b'\x00\x00\x00':
                self.reader.skip(3, f"{label}.BoolPad")
                print(f"{self.reader.indent_str * self.reader.indent_level}Type: '{type_str}' (Standard Pad)")
            else:
                print(f"{self.reader.indent_str * self.reader.indent_level}[Heuristic] Skipped Bool Padding (Next bytes: {peek_pad.hex()})")
                print(f"{self.reader.indent_str * self.reader.indent_level}Type: '{type_str}' (Compact/NoPad)")
            return bool(val_bool)

        elif type_str == 'enum':
            enum_type = self._read_class_id(f"{label}.EnumTy")
            enum_val = self._read_class_id(f"{label}.EnumVal")
            return {'type': 'enum', 'enumType': enum_type, 'value': enum_val}
        elif type_str == 'Objc':
             # [FIX] Objc has a flag and name
            flag = self.reader.read_u4(f"{label}.ObjFlag")
            obj_name = ""
            
            if flag == 1:
                # [Strategy] Check Table first, then Heuristic
                is_compact_name = False
                
                # 1. Table Check
                if label in self.KNOWN_OBJ_NAME_MODES:
                    if self.KNOWN_OBJ_NAME_MODES[label] == 'COMPACT':
                        print(f"{self.reader.indent_str * self.reader.indent_level}[Table] Key '{label}' implies COMPACT ObjName.")
                        is_compact_name = True
                else:
                    # 2. Heuristic (Original)
                    if self.reader.cursor + 8 <= self.reader.length:
                        peek_at_2 = self.reader.data[self.reader.cursor + 2 : self.reader.cursor + 6]
                        val_at_2 = struct.unpack('>I', peek_at_2)[0]
                        
                        peek_at_4 = self.reader.data[self.reader.cursor + 4 : self.reader.cursor + 8]
                        val_at_4 = struct.unpack('>I', peek_at_4)[0]
                        
                        score_2 = 0
                        if val_at_2 < 256: score_2 = 100
                        elif val_at_2 < 65536: score_2 = 50
                        
                        score_4 = 0
                        if val_at_4 < 256: score_4 = 100
                        elif val_at_4 < 65536: score_4 = 50
                        
                        if score_2 > score_4:
                            is_compact_name = True
                            print(f"{self.reader.indent_str * self.reader.indent_level}[Heuristic] Objc NameLen 2-byte alignment detected (00 00).")

                if is_compact_name:
                    self.reader.skip(2, "ObjName.ShortLen")
                else:
                    obj_name = self.reader.read_unicode_string(f"{label}.ObjName")
            
            desc_data = self.parse_descriptor(f"{label}.Obj")
            return {'type': 'Objc', 'name': obj_name, 'classID': desc_data['classID'], 'items': desc_data['items']}
        
        elif type_str == 'VlLs': 
            return self.parse_list(f"{label}.List")
        else:
            print(f"{self.reader.indent_str * self.reader.indent_level}[Warn] Unknown Type '{type_str}'")
            raise ValueError(f"Unknown OSType: {type_str}")

    def parse_list(self, label="List"):
        self.reader.indent()
        print(f"{self.reader.indent_str * self.reader.indent_level}--- {label} Start ---")
        
        count = self.reader.read_u4("List.Count")
        items = []
        
        for i in range(count):
            print(f"{self.reader.indent_str * self.reader.indent_level}List Item #{i}")
            try:
                peek_type = self.reader.peek_bytes(4)
                val = None
                if peek_type[0] == 0x0b and peek_type[1:4] == b'bru':
                    print(f"{self.reader.indent_str * self.reader.indent_level}[Heuristic] Compact Descriptor Detected!")
                    val = self._parse_compact_descriptor(f"Item{i}_Compact")
                else:
                    type_code = self.reader.read_ostype("ItemType")
                    val = self.parse_value_by_type(type_code, f"Item{i}")
                items.append(val)
            except Exception as e:
                print(f"{self.reader.indent_str * self.reader.indent_level}[Err] List Item #{i} Failed: {e}")
                self.reader.read_and_dump_full_bytes(64, "Error Context")
                raise e 
                
        print(f"{self.reader.indent_str * self.reader.indent_level}--- {label} End ---")
        self.reader.dedent()
        return items

    def _parse_compact_descriptor(self, label):
        self.reader.indent()
        print(f"{self.reader.indent_str * self.reader.indent_level}--- {label} (Compact) Start ---")
        
        name_len = self.reader.read_u1("ClassID.CompactLen")
        total_classid_bytes = 1
        
        class_id = ""
        if name_len > 0:
            class_id_bytes = self.reader.read_bytes(name_len, "ClassID.StrBytes")
            try: class_id = class_id_bytes.decode('utf-8')
            except: class_id = class_id_bytes.hex()
            total_classid_bytes += name_len
            print(f"{self.reader.indent_str * self.reader.indent_level}ClassID: '{class_id}'")
        
        padding = (4 - (total_classid_bytes % 4)) % 4
        if padding > 0:
            self.reader.skip(padding, "ClassID.Pad")
            
        body = self.parse_descriptor_body(label)
        self.reader.dedent()
        return {'classID': class_id, 'items': body}

    def _read_class_id(self, label):
        # [IMPROVED] Smart ClassID Length Detection (4-byte vs 2-byte)
        peek = self.reader.peek_bytes(4)
        is_short = False
        
        if len(peek) >= 4:
            b0, b1 = peek[0], peek[1]
            if b0 == 0 and b1 != 0:
                is_short = True
        
        class_id = ""
        if is_short:
             raw_len = self.reader.read_bytes(2, f"{label}.ShortLen")
             length = struct.unpack('>H', raw_len)[0]
             total_bytes = 2
             print(f"{self.reader.indent_str * self.reader.indent_level}[Heuristic] ClassID Short Length (2-byte) Detected: {length}")
        else:
             length = self.reader.read_u4(f"{label}.Len")
             total_bytes = 4
        
        if length == 0:
            class_id = self.reader.read_ostype(f"{label}.Code")
            total_bytes += 4
        else:
            val_bytes = self.reader.read_bytes(length, f"{label}.StrBytes")
            try: class_id = val_bytes.decode('utf-8')
            except: class_id = val_bytes.hex()
            print(f"{self.reader.indent_str * self.reader.indent_level}{label}.Val: '{class_id}'")
            total_bytes += length
            
        padding = (4 - (total_bytes % 4)) % 4
        if padding > 0:
            self.reader.skip(padding, f"{label}.Pad")
            
        return class_id

# ==============================================================================
# 4. Sequential Parser (Restored & Integrated)
# ==============================================================================

class SequentialAbrParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.items = []
        self.desc_data = [] # [NEW] Store Descriptor JSON structure
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
            elif key == 'desc': self.parse_8bimdesc_block(reader, length)
            elif key in ['titl', '8BIM']: reader.skip(length, f"Ignored ({key})", check_nonzero=False)
            else: reader.skip(length, f"Unknown ({key})")
            
            curr = reader.tell()
            rem = block_end - curr
            if rem > 0: 
                if key == 'desc': 
                    reader.skip(rem, "Block Trailing")
                else:
                    reader.skip(rem, "Block Trailing")
            elif rem < 0: print(f"    [Warn] Block over-read by {-rem} bytes")
            
            reader.cursor = block_end
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
            reader.cursor = item_end 
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
            self.parse_single_patt_item(reader, item_len, item_idx, item_end)
            rem = item_end - reader.tell()
            if rem > 0: self.parse_patt_trailing_data(reader, rem, item_end)
            pad = (4 - (item_len % 4)) % 4
            if pad > 0 and reader.tell() + pad <= target_end: reader.skip(pad, "Align Pad")
            reader.dedent(); item_idx += 1

    def parse_patt_trailing_data(self, reader, length, item_end_offset):
        print(f"    --- Item Trailing Metadata ({length} bytes) ---")
        reader.indent()
        TRAIL_PADDING = 91 
        VECTOR_HEADER_LEN = 12
        if length > TRAIL_PADDING:
            reader.skip(TRAIL_PADDING, "Initial Padding (Zeros)")
            remaining_to_read = item_end_offset - reader.tell()
            if remaining_to_read >= VECTOR_HEADER_LEN:
                print(f"    --- Vector Path Block ({remaining_to_read} bytes) ---")
                reader.indent()
                v_key = reader.read_u4("VKey") 
                v_len = reader.read_u4("VLen") 
                v_unk = reader.read_u4("VUnk")
                data_len = remaining_to_read - 12
                if data_len > 0:
                    # [Unified Interface Applied Here]
                    reader.read_and_dump_full_bytes(data_len, "Vector Shape Data (Compressed)")
                reader.dedent()
                print(f"    --- Vector Path Block End ---")
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
            if comp_mode == 1: 
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
            else: 
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
    
    def parse_8bimdesc_block(self, reader, block_len):
        print(f"    --- 8BIMdesc Parsing ({block_len} bytes) ---")
        start_pos = reader.tell()
        target_end = start_pos + block_len

        try:
            desc_ver = reader.read_u4("DescVersion")
            print(f"        Descriptor Version: {desc_ver}")
        except: return

        parser = ActionDescriptorParser(reader)
        idx = 0
        while reader.tell() < target_end:
            print(f"\n        [Desc #{idx}] Searching for descriptor...")
            if reader.tell() >= target_end: break
            
            desc_obj = None
            peek = reader.peek_bytes(5)
            
            try:
                if peek[0:4] == b'null':
                    print(f"        [Desc #{idx}] Detected Headless 'null' Descriptor!")
                    reader.read_str(4, "Implicit ClassID") 
                    body = parser.parse_descriptor_body(f"Descriptor_{idx}_Body")
                    desc_obj = {'classID': 'null', 'items': body}
                elif peek[0] == 0 and peek[1:5] == b'null':
                    print(f"        [Desc #{idx}] Detected Padding + Headless 'null' Descriptor!")
                    reader.skip(1, "Padding")
                    reader.read_str(4, "Implicit ClassID")
                    body = parser.parse_descriptor_body(f"Descriptor_{idx}_Body")
                    desc_obj = {'classID': 'null', 'items': body}
                else:
                    desc_obj = parser.parse_descriptor(f"Descriptor_{idx}")
                
                if desc_obj:
                    self.desc_data.append(desc_obj)
                    
            except Exception as e:
                print(f"        [Err] Parse Descriptor Failed: {e}")
                reader.read_and_dump_full_bytes(64, "Context")
                break
            idx += 1

    def save_json(self, out_dir="output", filename="desc_output.json"):
        if not os.path.exists(out_dir): os.makedirs(out_dir)
        out_path = os.path.join(out_dir, filename)
        print(f"\n{'='*80}\nSaving JSON to {out_path}...\n{'='*80}")
        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(self.desc_data, f, indent=4, ensure_ascii=False)
            print(f"[Success] Saved {len(self.desc_data)} descriptors to {out_path}")
        except Exception as e:
            print(f"[Err] Failed to save JSON: {e}")

    def save_images(self, out_dir="output"):
        if not os.path.exists(out_dir): os.makedirs(out_dir)
        print(f"\n{'='*80}\nSaving {len(self.items)} items...\n{'='*80}")
        for i, item in enumerate(self.items):
            arr = item['pix']
            if arr is None: continue
            safe_uuid = re.sub(r'[\\/*?:"<>|]', "_", str(item['uuid']))
            fname = os.path.join(out_dir, f"{safe_uuid}.png")
            # if os.path.exists(fname): fname = os.path.join(out_dir, f"{safe_uuid}_{i}.png")
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
        p.save_images(out_dir=sys.argv[1]+'-'+"output")
        p.save_json(out_dir=sys.argv[1]+'-'+"output")
