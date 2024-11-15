import os
import sqlite3
import sys
from PIL import Image
import numpy as np
import json
import zipfile
import tarfile
import shutil
def try_extract_zip(file_path, extract_dir):
    # 尝试解压ZIP文件
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        print(f"Extracted {file_path} to {extract_dir}")
    except zipfile.BadZipFile:
        print(f"No ZIP file found or {file_path} is corrupted.Exist:{os.path.exists(file_path)},isZIP{ zipfile.is_zipfile(file_path)}")
        
def try_extract_tar(file_path, extract_dir):
    # 尝试解压tar文件
    try:
        with tarfile.open(file_path, 'r:*') as tar_ref:
            tar_ref.extractall(extract_dir)
        print(f"Extracted {file_path} to {extract_dir}")
    except tarfile.TarError:
        print(f"No tar file found or {file_path} is corrupted.")
        
class XmlParser():
    def read_xml_from_file(file_path):
        with open(file_path, 'r', encoding='UTF-8') as file:
            xml_string = file.read()
        return xml_string
    def parse_xml_to_dict(xml_string):
        root = ET.fromstring(xml_string)
        info_dict = {}
        info_dict['version'] = root.find('version').text
        info = root.find('info')
        info_dict['uuid'] = info.get('uuid')
        for datalist in info.findall('datalist'):
            key = datalist.get('key')
            values = [data.text for data in datalist.findall('data')]
            info_dict[key] = values
        return info_dict
        
    def dict_to_xml(info_dict):
        root = ET.Element('infolist')
        version = ET.SubElement(root, 'version')
        version.text = info_dict['version']
        info = ET.SubElement(root, 'info', uuid=info_dict['uuid'])
        for key, values in info_dict.items():
            if key not in ['version', 'uuid']:
                datalist = ET.SubElement(info, 'datalist', key=key)
                for value in values:
                    data_ele = ET.SubElement(datalist, 'data')
                    data_ele.text = value
        return ET.tostring(root, encoding='utf-8').decode('utf-8')
    
class SutParser():
    """
    Parse textures and parameters from .sut files using sqlite
    """
    def __init__(self, filename):
        self.filename = filename
        self.brush_mats = []
        self.params = []
    
    def parse(self):
        base_dir = './cache'
        sut_name = os.path.basename(self.filename)
        cache_dir = os.path.join(base_dir, sut_name)
        
        # 在运行目录下的 cache 文件夹中创建与 sut 文件同名的文件夹
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

        if not os.path.exists(self.filename):
            print(f"Database file {self.filename} does not exist.")
            return
        
        con = sqlite3.connect(self.filename)
        cur = con.cursor()
        query = "SELECT name FROM sqlite_master WHERE type='table';"
        cur.execute(query)
        tables = cur.fetchall()
        tables_data = {}
        if not tables:
            print("No tables found.")
        else:
            for table in tables:                 
                table_name = table[0]
                if table_name=='sqlite_sequence':
                    continue;
                query = f"SELECT * FROM {table_name};"
                cur.execute(query)
                rows = cur.fetchall()
                columns = [description[0] for description in cur.description]

                
                table_data = []
                for row in rows:
                    row_data = {}
                    pw_id = row[columns.index('_PW_ID')]  # 获取当前行的_PW_ID值
                    for i, column in enumerate(columns):
                        if isinstance(row[i], bytes):
                            file_path = os.path.join(cache_dir, f"{table_name}-{column}-{pw_id}.bin")
                            with open(file_path, 'wb') as bin_file:
                                bin_file.write(row[i])
                            try_extract_tar(file_path, os.path.join(cache_dir,'binFile', f"{table_name}-{column}-{pw_id}.bin"))
                        else:
                            row_data[column] = row[i].decode('utf-8', errors='replace') if isinstance(row[i], bytes) else row[i]
                    table_data.append(row_data)
                tables_data[table_name] = table_data

        tables_json = json.dumps(tables_data, ensure_ascii=False, indent=4, sort_keys=True)
        json_file_path = os.path.join(cache_dir, sut_name + ".json")
        with open(json_file_path, 'w', encoding='utf-8') as file:
            file.write(tables_json)
       
        print(f"Database Tables Data saved to: {json_file_path}")
        con.close()

    def update_db(self):
        con = sqlite3.connect(self.filename)
        cur = con.cursor()

        base_dir = './cache'
        sut_name = os.path.basename(self.filename)
        cache_dir = os.path.join(base_dir, sut_name, 'binFile')

        # 遍历cache_dir目录下的所有文件夹
        for folder_name in os.listdir(cache_dir):
            folder_path = os.path.join(cache_dir, folder_name)
            if os.path.isdir(folder_path):
                tar_path = os.path.join(cache_dir, f"{folder_name}.tar")
                with tarfile.open(tar_path, "w") as tar:
                    # 添加文件夹下的所有文件到tar包，不包含文件夹本身
                    for file in os.listdir(folder_path):
                        file_path = os.path.join(folder_path, file)
                        tar.add(file_path, arcname=os.path.basename(file_path))
                
                # 读取tar文件内容，准备更新到数据库
                with open(tar_path, 'rb') as file:
                    tar_content = file.read()
                
                # 解析folder_name以找到表名、字段名和_PW_ID
                parts = folder_name.rsplit('-', 2)
                table_name, column_name, pw_id = parts[0], parts[1], parts[2].split('.')[0]
                
                # 构建SQL更新语句，将tar文件内容写回相应的BLOB字段
                sql_update = f"UPDATE {table_name} SET {column_name} = ? WHERE _PW_ID = ?"
                cur.execute(sql_update, (tar_content, pw_id))
                print(f"Updated {table_name} set {column_name} for _PW_ID {pw_id}")
        con.commit()
        con.close()
        print("Database update complete and connection closed.")

    def replace_material(self, image_path, pw_id, isAlpha=False):
        # 定位材质文件夹路径
        base_dir = './cache'
        sut_name = os.path.basename(self.filename)
        target_dir = os.path.join(base_dir, sut_name, 'binFile', f"MaterialFile-FileData-{pw_id}.bin", 'thumbnail')

        # 如果目标文件夹不存在，创建它
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
            print(f"Created directory {target_dir} because it did not exist.")

        # 确定新缩略图的目标路径
        target_image_path = os.path.join(target_dir, 'thumbnail.png')
        
        # 加载原始图像
        if os.path.exists(image_path):
            with Image.open(image_path) as img:
                # 如果需要处理透明度
                if isAlpha:
                    # 将图像转换为灰度图，然后使用灰度图的像素值设置 alpha 通道
                    grey_img = img.convert('L')
                    alpha_img = Image.new("RGBA", img.size)
                    for y in range(img.size[1]):
                        for x in range(img.size[0]):
                            pixel = grey_img.getpixel((x, y))
                            alpha_img.putpixel((x, y), (0, 0, 0, pixel))
                    alpha_img.save(target_image_path, format="PNG")
                    print(f"Created alpha image and saved to {target_image_path}.")
                else:
                    # 直接保存图像为 PNG 格式
                    img.convert('RGBA').save(target_image_path, format="PNG")
                    print(f"Replaced material thumbnail with {image_path} and saved as PNG to {target_image_path}.")
        else:
            print(f"Error: The provided image path {image_path} does not exist.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py filename.sut")
        sys.exit(1)
    
    filename = sys.argv[1]
    sParser = SutParser(filename)
    sParser.parse()
    sParser.replace_material(image_path='sample.jpg',pw_id=1,isAlpha=1)
    sParser.replace_material(image_path='sample.jpg',pw_id=2,isAlpha=1)
    sParser.replace_material(image_path='sample.jpg',pw_id=3,isAlpha=1)
    sParser.replace_material(image_path='sample.jpg',pw_id=4,isAlpha=1)
    sParser.update_db()