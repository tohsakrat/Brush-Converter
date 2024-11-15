import zipfile
import os
import plistlib
import sys
from PIL import Image
import json
import shutil
import sqlite3
import sys
from PIL import Image
import numpy as np
import json
import tarfile




class BrushsetParser:
    """
    Parse archived textures of Procreate brushes, extracting, resolving data, and handling bundled textures.
    """
    def __init__(self, filename):
        self.filename = filename
        self.cache = {}
        print(f"Initialized parser with file: {filename}")
    
    def check(self):
        is_zip = zipfile.is_zipfile(self.filename)
        print(f"Is the file a zip archive? {'Yes' if is_zip else 'No'}")
        return is_zip
    
    def parse(self):
        with zipfile.ZipFile(self.filename) as archive:
            result=[];
            namelist = archive.namelist()
            base_directory = os.path.join('cache', self.filename)  # 修改输出目录到 cache 文件夹下
            images_directory = "images"  # Simplified images directory path
            print(f"Creating base directory: {base_directory}")
            if not os.path.exists(base_directory):
                os.makedirs(base_directory)

            for member in namelist:
                if member.find('Reset') != -1:
                    continue
                dirname = os.path.dirname(member)
                full_path_dir = os.path.join(base_directory, dirname)
                if not os.path.exists(full_path_dir):
                    os.makedirs(full_path_dir)
                    print(f"Created directories for path: {full_path_dir}")

                if member.endswith('Shape.png') or member.endswith('Grain.png') or member.endswith('Brush.archive'):
                    full_out_path = os.path.join(base_directory, member)
                    if member.endswith('.png'):
                        with archive.open(member) as file:
                            img = Image.open(file)
                            img.save(full_out_path)
                            print(f"Saved image to {full_out_path}")
                    elif member.endswith('.archive'):
                        with archive.open(member) as file:
                            params = plistlib.load(file)
                            resolved_params = self.resolve_uids(params.get('$objects', []), params.get('$objects', [])[1])
                            params_file_name = os.path.splitext(full_out_path)[0] + '_resolved_params.json'
                            resolved_params=self.handle_bundled_textures(resolved_params, params_file_name)
                            sorted_params = json.dumps(resolved_params, indent=4, sort_keys=True) 
                            with open(params_file_name, 'w', encoding='utf-8') as file:
                                file.write(sorted_params)
                            print(f"Saved resolved params to {params_file_name}")
                            result.append(resolved_params)  # 将 resolved_params 添加到数组中

        return result  # 返回装有所有 resolved_params
                         

    def handle_bundled_textures(self, params, params_file_name):
        keys_to_check = ['bundledGrainPath', 'bundledShapePath']
        base_directory = os.path.dirname(params_file_name)
        for key in keys_to_check:
            source_path = os.path.join("images", os.path.basename(params[key]))
            target_path = os.path.join(base_directory, os.path.basename(params[key]))
            if key in params and params[key] != '$null':
                if os.path.exists(source_path):
                    shutil.copy(source_path, target_path)
                    print(f"Copied {source_path} to {target_path}")
                else:
                    print(f"File {source_path} not found, could not copy.")
            else:
                print(f"File {key.replace('bundled','').replace('Path','')} not found, try default image path.")
                default_image = key.replace('bundled','').replace('Path','')+".png"
                default_image_path = os.path.join(base_directory, default_image)
                if os.path.exists(default_image_path):
                    params[key] = default_image
                    print(f"Default image {default_image} found")
                else:
                    print(f"Default image {default_image_path} is not available, no changes made.")
        return params;

    def resolve_uids(self, objects, obj):
        if isinstance(obj, plistlib.UID):
            return self.resolve_uids(objects, objects[obj.data])
        elif isinstance(obj, dict):
            return {k: self.resolve_uids(objects, v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return [self.resolve_uids(objects, item) for item in obj]
        elif isinstance(obj, bytes):
            return obj.hex()  # Convert bytes to hex string for clearer display
        else:
            return obj

def main():
    if len(sys.argv) < 2:
        print("Usage: python brushset_parser.py [FILENAME]")
        sys.exit(1)

    filename = sys.argv[1]
    bparser = BrushsetParser(filename)
    if bparser.check():
        paramsList = bparser.parse()
        #print('skipped')
    else:
        print("Provided file is not a valid zip file.")
        return

    target_folder = os.path.join('cache', filename)
    if not os.path.exists(target_folder):
        print("No target directory found.")
        return
"""
    # 遍历 target_folder 下的所有一级子文件夹
    for subdir in os.listdir(target_folder):
        print(subdir)
        subdir_path = os.path.join(target_folder, subdir)
        if os.path.isdir(subdir_path):
            # 复制 sample.sut 文件到当前文件夹并重命名
            # 获取运行时工作目录的绝对路径
            current_dir = os.path.dirname(os.path.realpath(__file__))
            # 创建目标文件夹路径
            target_folder = os.path.join('cache', filename)
            full_target_path = os.path.join(current_dir, target_folder)
            
            if not os.path.exists(full_target_path):
                print(f"No target directory found.{full_target_path}")
                return

            # 确保 sample.sut 文件存在
            sample_sut_path = os.path.join(current_dir, 'sample.sut')
            if not os.path.exists(sample_sut_path):
                print("Error: sample.sut file does not exist in the script directory.")
                return

            # 复制 sample.sut 文件并直接以新的文件名保存到目标目录，覆盖同名文件
            new_sample_path = os.path.join(full_target_path, subdir + '.sut')
            shutil.copy2(sample_sut_path, new_sample_path)
            print(f"sample.sut has been copied and renamed to {new_sample_path}")
            # 读取和解析 JSON 文件中的路径
            json_file = os.path.join(subdir_path, "Brush_resolved_params.json")
            if os.path.exists(json_file):
                with open(json_file, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                brushGrain = None
                brushShape = None
                subBrushGrain = None
                subBrushShape = None

                # 处理主文件夹下的 Grains 和 Shapes
                if data['bundledGrainPath'] != '$null':
                    grain_path = os.path.join(subdir_path, os.path.basename(data['bundledGrainPath']))
                    if os.path.exists(grain_path):
                        brushGrain = Image.open(grain_path)
                        print(f"Loaded main brush grain image from {grain_path}")
                else:
                    print("No main brush grain path provided or it is set to '$null'.")

                if data['bundledShapePath'] != '$null':
                    shape_path = os.path.join(subdir_path, os.path.basename(data['bundledShapePath']))
                    if os.path.exists(shape_path):
                        brushShape = Image.open(shape_path)
                        print(f"Loaded main brush shape image from {shape_path}")
                else:
                    print("No main brush shape path provided or it is set to '$null'.")

                # 处理 Sub01 文件夹下的 Grains 和 Shapes
                sub_dir = os.path.join(subdir_path, "Sub01")
                if os.path.isdir(sub_dir):
                    sub_json_file = os.path.join(sub_dir, "Brush_resolved_params.json")
                    if os.path.exists(sub_json_file):
                        with open(sub_json_file, 'r', encoding='utf-8') as file:
                            sub_data = json.load(file)
                        if sub_data['bundledGrainPath'] != '$null':
                            sub_grain_path = os.path.join(sub_dir, os.path.basename(sub_data['bundledGrainPath']))
                            if os.path.exists(sub_grain_path):
                                subBrushGrain = Image.open(sub_grain_path)
                                print(f"Loaded sub brush grain image from {sub_grain_path}")
                        else:
                            print("No sub brush grain path provided or it is set to '$null'.")

                        if sub_data['bundledShapePath'] != '$null':
                            sub_shape_path = os.path.join(sub_dir, os.path.basename(sub_data['bundledShapePath']))
                            if os.path.exists(sub_shape_path):
                                subBrushShape = Image.open(sub_shape_path)
                                print(f"Loaded sub brush shape image from {sub_shape_path}")
                        else:
                            print("No sub brush shape path provided or it is set to '$null'.")
            else:
                print(f"No Brush_resolved_params.json found in {subdir_path}")
          """      
    

if __name__ == "__main__":
    main()