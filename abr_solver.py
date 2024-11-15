
import struct
import sys
import numpy as np
from PIL import Image

def rle_decode(bytes, img_H, img_W, depth):
    dtype = '>u'+str(depth//8)
    img_mat = np.zeros((img_H, img_W), dtype=dtype)
    line_byte_count = np.frombuffer(bytes, dtype='>u2', count=img_H)
    offset = img_H * 2
    
    total_bytes = 0  # 记录总的字节数
    
    for i in range(img_H):
        end_position = offset + line_byte_count[i]
        total_bytes += line_byte_count[i]  # 累加每行的字节数
        j = 0
        while offset < end_position:
            n = struct.unpack_from('>B', bytes, offset)[0]
            offset += 1
            if n == 128:
                continue
            elif n < 128:       # 非压缩数据 (n+1) 个数
                img_mat[i][j:j+n+1] = np.frombuffer(bytes, dtype=dtype, count=n+1, offset=offset)
                offset += (n+1)*(depth//8)
                j += (n+1)
            else:               # 压缩数据 (n+1) 次
                n = (256-n)
                img_mat[i][j:j+n+1] = np.frombuffer(bytes, dtype=dtype, count=1, offset=offset)
                offset += (depth//8)
                j += (n+1)
    
    return total_bytes, img_mat


class AbrParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.brushes = []

    def unpack(self, format_string, data, offset):
        length = struct.calcsize(format_string)
        res = struct.unpack(format_string, data[offset: offset + length])
        return res if len(res) > 1 else res[0], offset + length

    def parse(self):
        with open(self.filepath, 'rb') as f:
            data = f.read()
            offset = 0

            # 读取文件头
            major_version, offset = self.unpack('>H', data, offset)
            minor_version, offset = self.unpack('>H', data, offset)
            identifier, offset = self.unpack('>4s', data, offset)
            block_name, offset = self.unpack('>4s', data, offset)
            samp_block_length, offset = self.unpack('>I', data, offset)

            print(f"Identifier: {identifier.decode('ascii')}")
            print(f"Block Name: {block_name.decode('ascii')}")
            print(f"Version: {major_version}.{minor_version}")
            print(f"Sample Block Length: {samp_block_length}")

            end_position = offset + samp_block_length

            while offset < end_position:
                brush_length, offset = self.unpack('>I', data, offset)
                if brush_length % 4:
                    brush_length += (4 - brush_length % 4)
                next_offset = offset + brush_length
                # 解析笔刷数据
                abr_skipped_bytes = {1: 47, 2: 301}
                
                offset += abr_skipped_bytes[minor_version]
                # bounds 16byte
                top, offset = self.unpack('>I', data, offset)
                left, offset = self.unpack('>I', data, offset)
                bottom, offset = self.unpack('>I', data, offset)
                right, offset = self.unpack('>I', data, offset)
                # depth 2byte
                depth, offset = self.unpack('>H', data, offset)
                compression, offset = self.unpack('>B', data, offset)
                dtype = '>u'+str(depth//8)
                img_H, img_W = bottom-top, right-left
                if compression == 0:      # No compression
                    total_bytes=img_H*img_W
                    pixels_1d = np.frombuffer(data, dtype=dtype, count=total_bytes, offset=offset).reshape((img_H, img_W))
                    
                elif compression == 1:    # RLE compression
                    total_bytes,pixels_1d = rle_decode(data[offset:offset+brush_length], img_H, img_W, depth)
                offset+=total_bytes;
                setting = data[offset: next_offset]
                brush_info = {
                    'top': top,
                    'left': left,
                    'bottom': bottom,
                    'right': right,
                    'depth': depth,
                    'compression': compression,
                    'pixel_data': data[offset:next_offset],
                    'dtype': dtype,
                    'pix': pixels_1d,
                    'setting': setting
                }
                self.brushes.append(brush_info)

                offset = next_offset

    def save_brushes_as_png(self):
        for i, brush in enumerate(self.brushes):
            img = Image.fromarray(brush['pix'])
            img = img.convert("L")  # Convert to grayscale
            img.save(f"brush_{i + 1}.png")

    def display_brushes(self):
        for i, brush in enumerate(self.brushes):
            print(f"Brush {i + 1}:")
            print(f"  Top: {brush['top']}")
            print(f"  Left: {brush['left']}")
            print(f"  Bottom: {brush['bottom']}")
            print(f"  Right: {brush['right']}")
            print(f"  Depth: {brush['depth']}")
            print(f"  Compression: {brush['compression']}")
            print(f"  dtype: {brush['dtype']}")
            # 打印 setting 的前100个字节
            setting = brush['setting']
            ascii_representation =  setting
            print(f"  setting (First 100 bytes): { ascii_representation}")
          #  print(f"  pix (First 100 bytes): {brush['pix']}")

            offset = 0

            # 解析 setting
            continue;
            brush_type, offset = self.unpack('>H', setting, offset)
            brush_size, offset = self.unpack('>I', setting, offset)

            if brush_type == 1:
                # 解析 Computed brush
                if offset + 14 > len(setting):
                    break
                miscellaneous, offset = self.unpack('>I', setting, offset)
                spacing, offset = self.unpack('>H', setting, offset)
                diameter, offset = self.unpack('>H', setting, offset)
                roundness, offset = self.unpack('>H', setting, offset)
                angle, offset = self.unpack('>H', setting, offset)
                hardness, offset = self.unpack('>H', setting, offset)
                
                print(f"  Computed Brush:")
                print(f"    Miscellaneous: {miscellaneous}")
                print(f"    Spacing: {spacing}")
                print(f"    Diameter: {diameter}")
                print(f"    Roundness: {roundness}")
                print(f"    Angle: {angle}")
                print(f"    Hardness: {hardness}")

            elif brush_type == 2:
                # 解析 Sampled brush
                if offset + 31 > len(setting):
                    break
                miscellaneous, offset = self.unpack('>I', setting, offset)
                spacing, offset = self.unpack('>H', setting, offset)
                anti_aliasing, offset = self.unpack('>B', setting, offset)
                bounds = struct.unpack('>4H', setting[offset:offset + 8])
                offset += 8
                bounds_long = struct.unpack('>4I', setting[offset:offset + 16])
                offset += 16
                depth, offset = self.unpack('>H', setting, offset)
                
                print(f"  Sampled Brush:")
                print(f"    Miscellaneous: {miscellaneous}")
                print(f"    Spacing: {spacing}")
                print(f"    Anti-aliasing: {anti_aliasing}")
                print(f"    Bounds: {bounds}")
                print(f"    Bounds Long: {bounds_long}")
                print(f"    Depth: {depth}")

                # 处理剩余的像素数据
                #remaining_data = setting[offset:offset + brush_size - 31]
                #print(f"    Remaining Data (Hex): {remaining_data.hex()}")
                #offset += brush_size - 31

            else:
                print(f"  Unknown Brush Type: {brush_type}")
                offset += brush_size
                
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python abr_parser.py <path_to_abr_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    parser = AbrParser(filepath)
    parser.parse()
    parser.display_brushes()
    parser.save_brushes_as_png()