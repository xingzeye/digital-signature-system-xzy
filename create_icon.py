import os
from PIL import Image

def create_icon():
    # 确保resources目录存在
    if not os.path.exists('resources'):
        os.makedirs('resources')
    
    # 加载你的图片
    original_image = Image.open(r"1.jpg")
    
    # 如果图片是CMYK模式，转换为RGB
    if original_image.mode == 'CMYK':
        original_image = original_image.convert('RGB')
    
    # 创建不同尺寸的图标
    icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64)]
    icons = []
    
    for size in icon_sizes:
        # 调整图片大小
        resized_image = original_image.resize(size, Image.Resampling.LANCZOS)
        # 确保图像是RGB模式
        if resized_image.mode != 'RGB':
            resized_image = resized_image.convert('RGB')
        icons.append(resized_image)
    
    # 保存为.ico文件
    icon_path = os.path.join('resources', 'signature.ico')
    try:
        icons[0].save(icon_path, format='ICO', sizes=icon_sizes, append_images=icons[1:])
        print(f"图标创建成功: {icon_path}")
    except Exception as e:
        print(f"创建图标时出错: {e}")
        return None
    
    return icon_path

if __name__ == '__main__':
    icon_path = create_icon()
    if icon_path:
        print(f"图标已创建: {icon_path}")
    else:
        print("图标创建失败") 