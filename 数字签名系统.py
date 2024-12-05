import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, font
from PIL import Image, ImageTk
from Crypto.Hash import SHA256
from gmssl import sm2, func  # 导入SM2用于加密操作
from Crypto.Cipher import ARC4
import base64
import os
import random
from hashlib import sha256
from gmpy2 import invert, is_prime
from create_icon import create_icon
import sys

def resource_path(relative_path):
    """获取资源的绝对路径"""
    try:
        # PyInstaller创建临时文件夹,将路径存储在_MEIPASS中
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# 全局变量
sm2_crypt = None  # SM2加密对象
private_key = None
public_key = None
signature = None
hash_value = None
original_hash = None

# SM2参数
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# 函数：椭圆曲线上两点相加
def point_add(P1x, P1y, P2x, P2y):
    if P1x == 0 and P1y == 0:
        return P2x, P2y
    if P2x == 0 and P2y == 0:
        return P1x, P1y
    
    if P1x == P2x and P1y != P2y:
        return 0, 0
        
    if P1x != P2x:
        lam = ((P2y - P1y) * invert(P2x - P1x, p)) % p
    else:
        lam = ((3 * P1x * P1x + a) * invert(2 * P1y, p)) % p
        
    x3 = (lam * lam - P1x - P2x) % p
    y3 = (lam * (P1x - x3) - P1y) % p
    
    return x3, y3

# 函数：椭圆曲线上点乘标量
def point_mul(k, Px, Py):
    Qx, Qy = 0, 0
    k_bin = bin(k)[2:]
    
    for i in k_bin:
        Qx, Qy = point_add(Qx, Qy, Qx, Qy)
        if i == '1':
            Qx, Qy = point_add(Qx, Qy, Px, Py)
            
    return Qx, Qy

# 函数：生成密钥对
def generate_key():
    private_key = random.randint(1, n-1)
    public_key = point_mul(private_key, Gx, Gy)
    return private_key, public_key

# 函数：使用SM2签名消息哈希
def sm2_sign(message_hash, private_key, k=None):
    if k is None:
        k = random.randint(1, n-1)
    
    x1, y1 = point_mul(k, Gx, Gy)
    r = (int(message_hash, 16) + x1) % n
    if r == 0 or r + k == n:
        return sm2_sign(message_hash, private_key)
    
    s = (invert(1 + private_key, n) * (k - r * private_key)) % n
    if s == 0:
        return sm2_sign(message_hash, private_key)
    
    return (hex(r)[2:].zfill(64), hex(s)[2:].zfill(64))

# 函数：使用SM2验证签名
def sm2_verify(message_hash, signature, public_key):
    r, s = int(signature[0], 16), int(signature[1], 16)
    
    if r < 1 or r > n-1 or s < 1 or s > n-1:
        return False
    
    t = (r + s) % n
    if t == 0:
        return False
    
    x1, y1 = point_mul(s, Gx, Gy)
    x2, y2 = point_mul(t, public_key[0], public_key[1])
    x, y = point_add(x1, y1, x2, y2)
    
    R = (int(message_hash, 16) + x) % n
    return R == r

# 函数：使用用户ID生成密钥
def generate_keys_with_id(user_id):
    global private_key, public_key, rc4_key
    try:
        # 基于用户ID生成种子
        if not user_id:
            raise ValueError("请输入用户ID")
        
        # 生成密钥对
        private_key, public_key = generate_key()
        
        # 生成RC4密钥
        rc4_key = os.urandom(16)
        
        # 显示密钥
        public_key_box.delete('1.0', tk.END)
        private_key_box.delete('1.0', tk.END)
        rc4_key_box.delete('1.0', tk.END)
        
        public_key_box.insert(tk.END, f"04{hex(public_key[0])[2:].zfill(64)}{hex(public_key[1])[2:].zfill(64)}")
        private_key_box.insert(tk.END, hex(private_key)[2:].zfill(64))
        rc4_key_box.insert(tk.END, base64.b64encode(rc4_key).decode('utf-8'))
        
        print(f"用户 {user_id} 的密钥生成成功")
    except Exception as e:
        print(f"密钥生成失败: {e}")

# 函数：从文件加载明文
def load_plain_text_from_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r', encoding='utf-8') as file:
            file_content = file.read()
            plain_text_box.delete('1.0', tk.END)
            plain_text_box.insert(tk.END, file_content)

# 函数：计算SHA256哈希
def sha_hash():
    global hash_value
    try:
        plain_text = plain_text_box.get('1.0', tk.END).strip().encode()
        hash_obj = SHA256.new(plain_text)
        hash_value = hash_obj.digest()  # 保存二进制哈希值
        sha_result_box.delete('1.0', tk.END)
        sha_result_box.insert(tk.END, hash_obj.hexdigest())  # 显示十六进制形式
        print("哈希计算成功")
    except Exception as e:
        print(f"哈希计算失败: {e}")

# 函数：使用SM2签名哈希值
def sm2_sign_h1():
    global signature
    if not private_key:
        print("请先生成密钥")
        return
    try:
        if not hash_value:
            print("请先计算哈希值")
            return
        
        # 对哈希值进行签名
        hash_hex = hash_value.hex()
        r, s = sm2_sign(hash_hex, private_key)  # 获取签名的r和s部分
        signature = r + s  # 将r和s拼接成一个字符串
        
        sm2_result_box.delete('1.0', tk.END)
        sm2_result_box.insert(tk.END, signature)
        print("签名生成成功")
    except Exception as e:
        print(f"签名生成失败: {e}")
        sm2_result_box.delete('1.0', tk.END)
        sm2_result_box.insert(tk.END, f"签名失败: {str(e)}")

# 函数：使用RC4加密
def rc4_encrypt_e1():
    if not rc4_key or not signature:
        print("请先生成密钥和签")
        return
    try:
        # 获取明文m
        plain_text = plain_text_box.get('1.0', tk.END).strip().encode()
        # 获取签名d1（已经是十六进制格式的字符串）
        signature_bytes = bytes.fromhex(signature)  # 直接转换拼接后的签名字符串
        # 串联m和d1形成e1
        e1 = plain_text + signature_bytes
        # RC4加密e1得到c1
        cipher = ARC4.new(rc4_key)
        ciphertext = cipher.encrypt(e1)
        final_result_box.delete('1.0', tk.END)
        final_result_box.insert(tk.END, base64.b64encode(ciphertext).decode('utf-8'))
    except Exception as e:
        print(f"加密过程发生错误: {e}")

# 函数：保存数据到文件
def save_to_file():
    try:
        if not hash_value or not signature:
            print("请先完成哈希和签名")
            return
            
        file_content = (
            "公钥:\n" + public_key_box.get('1.0', tk.END).strip() + "\n\n" +
            "私钥:\n" + private_key_box.get('1.0', tk.END).strip() + "\n\n" +
            "RC4密钥:\n" + rc4_key_box.get('1.0', tk.END).strip() + "\n\n" +
            "哈希值:\n" + base64.b64encode(hash_value).decode('utf-8') + "\n\n" +  # 保存二进制哈希
            "数字签名:\n" + signature + "\n\n" +  # 签名已经字符串格式
            "加密结果:\n" + final_result_box.get('1.0', tk.END).strip()
        )
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(file_content)
            print("文件保存成功")
    except Exception as e:
        print(f"文件保存失败: {e}")

# 函数：从文件加载密钥和密文
def load_keys_and_ciphertext():
    global private_key, public_key, original_hash, rc4_key
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            sections = content.split("\n\n")
            for section in sections:
                if section.startswith("公钥:"):
                    pub_key_str = section.split("公钥:\n")[1].strip()
                    # 解析公钥字符串（去掉'04'前缀）
                    pub_key_hex = pub_key_str[2:]  # 去掉'04'前缀
                    x_hex = pub_key_hex[:64]  # 前64个字符是x坐标
                    y_hex = pub_key_hex[64:]  # 后64个字符是y坐标
                    # 转换为整数坐标
                    public_key = (int(x_hex, 16), int(y_hex, 16))
                    public_key_box_verify.delete('1.0', tk.END)
                    public_key_box_verify.insert(tk.END, pub_key_str)
                elif section.startswith("私钥:"):
                    private_key = int(section.split("私钥:\n")[1].strip(), 16)
                    private_key_box_verify.delete('1.0', tk.END)
                    private_key_box_verify.insert(tk.END, hex(private_key)[2:].zfill(64))
                elif section.startswith("RC4密钥:"):
                    rc4_key = base64.b64decode(section.split("RC4密钥:\n")[1].strip())
                    rc4_key_box_verify.delete('1.0', tk.END)
                    rc4_key_box_verify.insert(tk.END, section.split("RC4密钥:\n")[1].strip())
                elif section.startswith("哈希值:"):
                    original_hash = base64.b64decode(section.split("哈希值:\n")[1].strip())
                    hash_display_box.delete('1.0', tk.END)
                    hash_display_box.insert(tk.END, original_hash.hex())
                elif section.startswith("加密结果:"):
                    ciphertext_box.delete('1.0', tk.END)
                    ciphertext_box.insert(tk.END, section.split("加密结果:\n")[1].strip())
            print("数据加载成功")

# 函数：使用RC4解密
def rc4_decrypt_c2():
    """
    RC4解密函数
    使用文本框中的RC4密钥进行解密
    """
    try:
        # 1. 获取RC4密钥
        rc4_key_str = rc4_key_box_verify.get('1.0', tk.END).strip()
        if not rc4_key_str:
            raise ValueError("RC4密钥未输入")
        try:
            current_rc4_key = base64.b64decode(rc4_key_str)
        except:
            raise ValueError("RC4密钥格式错误")

        # 2. 获取密文
        encrypted_text = ciphertext_box.get('1.0', tk.END).strip()
        if not encrypted_text:
            raise ValueError("密文未输入")
        try:
            ciphertext = base64.b64decode(encrypted_text)
        except:
            raise ValueError("密文格式错误")

        # 3. RC4解密
        cipher = ARC4.new(current_rc4_key)
        decrypted_text = cipher.decrypt(ciphertext)
        
        # 4. 分离明文和签名
        try:
            signature_length = 128  # SM2签名的十六进制字符串长度为128
            m = decrypted_text[:-signature_length//2]  # 因为是字节形式，所以长度要除以2
            d1 = decrypted_text[-signature_length//2:]
        except:
            raise ValueError("解数据长度错误")
        
        # 5. 显示结果
        try:
            plain_text_box_verify.delete('1.0', tk.END)
            plain_text_box_verify.insert(tk.END, m.decode('utf-8', errors='ignore'))
            signature_box.delete('1.0', tk.END)
            signature_box.insert(tk.END, d1.hex())
            print("解密成功")
        except:
            raise ValueError("解密数据格式错误")
            
    except ValueError as ve:
        print(f"解密错误: {ve}")
        plain_text_box_verify.delete('1.0', tk.END)
        signature_box.delete('1.0', tk.END)
        plain_text_box_verify.insert(tk.END, f"解密失败: {str(ve)}")
    except Exception as e:
        print(f"解密过程中发生错误: {e}")
        plain_text_box_verify.delete('1.0', tk.END)
        signature_box.delete('1.0', tk.END)
        plain_text_box_verify.insert(tk.END, f"解密失败: {str(e)}")

# 函数：使用SM2验证签名
def sm2_verify_signature():
    """
    SM2签名验证函数
    实时从文本框读取所有数据进行验证
    """
    try:
        # 1. 验证公钥
        pub_key_str = public_key_box_verify.get('1.0', tk.END).strip()
        if not pub_key_str:
            raise ValueError("公钥未输入")
        if not pub_key_str.startswith('04'):
            raise ValueError("公钥格式错误，应以'04'开头")
            
        # 解析公坐标
        pub_key_hex = pub_key_str[2:]
        if len(pub_key_hex) != 128:
            raise ValueError("公钥长度错误")
        x_hex = pub_key_hex[:64]
        y_hex = pub_key_hex[64:]
        current_public_key = (int(x_hex, 16), int(y_hex, 16))

        # 2. 验证签名
        signature_str = signature_box.get('1.0', tk.END).strip()
        if not signature_str:
            raise ValueError("签名未输入")
        if len(signature_str) != 128:
            raise ValueError("签名长度错误")
            
        # 分离r和s
        r = signature_str[:64]
        s = signature_str[64:]

        # 3. 验证文
        plain_text = plain_text_box_verify.get('1.0', tk.END).strip()
        if not plain_text:
            raise ValueError("明文未输入")

        # 4. 计算当前明文的哈希值
        current_hash = SHA256.new(plain_text.encode()).digest()
        
        # 5. 获取显示的哈希值
        displayed_hash_str = hash_display_box.get('1.0', tk.END).strip()
        if not displayed_hash_str:
            raise ValueError("哈希值未显示")

        # 6. 比较哈希值
        if current_hash.hex() != displayed_hash_str:
            verification_result_box.delete('1.0', tk.END)
            verification_result_box.insert(tk.END, "验证失败：明文被修改\n"
                                               f"当前哈希: {current_hash.hex()}\n"
                                               f"原始哈希: {displayed_hash_str}")
            return

        # 7. 验证签名
        verify_result = sm2_verify(current_hash.hex(), (r, s), current_public_key)
        
        # 8. 显���验证结果
        verification_result_box.delete('1.0', tk.END)
        if verify_result:
            verification_result_box.insert(tk.END, "验证成功\n"
                                               "1. 明文未被修改\n"
                                               "2. 签名验证过")
        else:
            verification_result_box.insert(tk.END, "验证失败\n"
                                               "1. 明文未被修改\n"
                                               "2. 签名验证失败")

    except ValueError as ve:
        print(f"验证错误: {ve}")
        verification_result_box.delete('1.0', tk.END)
        verification_result_box.insert(tk.END, f"验证失败: {str(ve)}")
    except Exception as e:
        print(f"验证过程发生误: {e}")
        verification_result_box.delete('1.0', tk.END)
        verification_result_box.insert(tk.END, f"验证失败: {str(e)}")

# 函数：显示特定框架
def show_frame(frame):
    frame.tkraise()

# 创建主窗口
root = tk.Tk()
root.title("数字签名系统")
root.geometry("1200x800")

# 设置图标
icon_path = resource_path(os.path.join('resources', 'signature.ico'))
if os.path.exists(icon_path):
    root.iconbitmap(icon_path)

# 设置主题样式
style = ttk.Style()
style.theme_use('clam')

# ���建主框架
main_frame = ttk.Frame(root)
main_frame.pack(fill='both', expand=True, padx=20, pady=20)

# 创建标题
title_font = font.Font(family='Helvetica', size=24, weight='bold')
title_label = ttk.Label(main_frame, text="数字签名系统", font=title_font)
title_label.pack(pady=20)

# 创建Notebook用于切换页面
notebook = ttk.Notebook(main_frame)
notebook.pack(fill='both', expand=True)

# 签名页面和验证页面
sign_frame = ttk.Frame(notebook)
verify_frame = ttk.Frame(notebook)
notebook.add(sign_frame, text='签名系统')
notebook.add(verify_frame, text='验证系统')

# 签名界面布局
sign_content = ttk.Frame(sign_frame)
sign_content.pack(fill='both', expand=True, padx=20, pady=20)

# 左侧板 - 密钥管理
left_panel = ttk.LabelFrame(sign_content, text="密钥管理")
left_panel.pack(side='left', fill='y', padx=(0,10))

ttk.Label(left_panel, text="用户ID：").pack(pady=5)
user_id_entry = ttk.Entry(left_panel)
user_id_entry.pack(pady=5)
ttk.Button(left_panel, text="生成密钥", command=lambda: generate_keys_with_id(user_id_entry.get())).pack(pady=5)

ttk.Label(left_panel, text="公钥：").pack(pady=5)
public_key_box = scrolledtext.ScrolledText(left_panel, width=30, height=4)
public_key_box.pack(pady=5)

ttk.Label(left_panel, text="私钥：").pack(pady=5)
private_key_box = scrolledtext.ScrolledText(left_panel, width=30, height=4)
private_key_box.pack(pady=5)

ttk.Label(left_panel, text="RC4密钥：").pack(pady=5)
rc4_key_box = scrolledtext.ScrolledText(left_panel, width=30, height=2)
rc4_key_box.pack(pady=5)

# 中间面板 - 操作区域
middle_panel = ttk.LabelFrame(sign_content, text="操作区域")
middle_panel.pack(side='left', fill='both', expand=True)

ttk.Label(middle_panel, text="明文信息：").pack(pady=5)
plain_text_box = scrolledtext.ScrolledText(middle_panel, height=4)
plain_text_box.pack(fill='x', pady=5)
ttk.Button(middle_panel, text="上传文件", command=load_plain_text_from_file).pack(pady=5)

button_frame = ttk.Frame(middle_panel)
button_frame.pack(pady=10)
ttk.Button(button_frame, text="SHA哈希", command=sha_hash).pack(side='left', padx=5)
ttk.Button(button_frame, text="SM2签名", command=sm2_sign_h1).pack(side='left', padx=5)
ttk.Button(button_frame, text="RC4加密", command=rc4_encrypt_e1).pack(side='left', padx=5)
ttk.Button(button_frame, text="保存到文件", command=save_to_file).pack(side='left', padx=5)

# 右侧面板 - 结果示
right_panel = ttk.LabelFrame(sign_content, text="结果显示")
right_panel.pack(side='right', fill='y', padx=(10,0))

ttk.Label(right_panel, text="SHA256哈希结果：").pack(pady=5)
sha_result_box = scrolledtext.ScrolledText(right_panel, width=30, height=2)
sha_result_box.pack(pady=5)

ttk.Label(right_panel, text="SM2签名结果：").pack(pady=5)
sm2_result_box = scrolledtext.ScrolledText(right_panel, width=30, height=2)
sm2_result_box.pack(pady=5)

ttk.Label(right_panel, text="RC4加密结果：").pack(pady=5)
final_result_box = scrolledtext.ScrolledText(right_panel, width=30, height=2)
final_result_box.pack(pady=5)

# 验证界面布局
verify_content = ttk.Frame(verify_frame)
verify_content.pack(fill='both', expand=True, padx=20, pady=20)

# 左侧面 - 密钥信息
verify_left_panel = ttk.LabelFrame(verify_content, text="密钥信息")
verify_left_panel.pack(side='left', fill='y', padx=(0,10))

ttk.Button(verify_left_panel, text="加载密钥和密文", command=load_keys_and_ciphertext).pack(pady=10)

ttk.Label(verify_left_panel, text="公钥：").pack(pady=5)
public_key_box_verify = scrolledtext.ScrolledText(verify_left_panel, width=30, height=2)
public_key_box_verify.pack(pady=5)

ttk.Label(verify_left_panel, text="私钥：").pack(pady=5)
private_key_box_verify = scrolledtext.ScrolledText(verify_left_panel, width=30, height=2)
private_key_box_verify.pack(pady=5)

ttk.Label(verify_left_panel, text="RC4密钥：").pack(pady=5)
rc4_key_box_verify = scrolledtext.ScrolledText(verify_left_panel, width=30, height=2)
rc4_key_box_verify.pack(pady=5)

# 中间面板 - 验证操作
verify_middle_panel = ttk.LabelFrame(verify_content, text="验证操作")
verify_middle_panel.pack(side='left', fill='both', expand=True)

ttk.Label(verify_middle_panel, text="密文：").pack(pady=5)
ciphertext_box = scrolledtext.ScrolledText(verify_middle_panel, height=3)
ciphertext_box.pack(fill='x', pady=5)

ttk.Button(verify_middle_panel, text="RC4解密", command=rc4_decrypt_c2).pack(pady=10)
ttk.Button(verify_middle_panel, text="SM2公钥验证签名", command=sm2_verify_signature).pack(pady=10)

# 右侧面板 - 验证结果
verify_right_panel = ttk.LabelFrame(verify_content, text="验证结果")
verify_right_panel.pack(side='right', fill='y', padx=(10,0))

ttk.Label(verify_right_panel, text="明文：").pack(pady=5)
plain_text_box_verify = scrolledtext.ScrolledText(verify_right_panel, width=30, height=2)
plain_text_box_verify.pack(pady=5)

ttk.Label(verify_right_panel, text="签名：").pack(pady=5)
signature_box = scrolledtext.ScrolledText(verify_right_panel, width=30, height=2)
signature_box.pack(pady=5)

ttk.Label(verify_right_panel, text="哈希：").pack(pady=5)
hash_display_box = scrolledtext.ScrolledText(verify_right_panel, width=30, height=2)
hash_display_box.pack(pady=5)

ttk.Label(verify_right_panel, text="验证结果：").pack(pady=5)
verification_result_box = scrolledtext.ScrolledText(verify_right_panel, width=30, height=2)
verification_result_box.pack(pady=5)

# 设置背景图片
bg_image = Image.open(resource_path('./resources/1.jpg'))
bg_image = bg_image.resize((root.winfo_screenwidth(), root.winfo_screenheight()))
bg_photo = ImageTk.PhotoImage(bg_image)
# 保持对背景图片的全局引用，防止被垃圾回收
root.bg_photo = bg_photo
# 设置所有组件的透明
for widget in [sign_frame, verify_frame]:
    widget.configure(style='Transparent.TLabelframe')
    for child in widget.winfo_children():
        if isinstance(child, ttk.LabelFrame):
            child.configure(style='Transparent.TLabelframe')
        elif isinstance(child, scrolledtext.ScrolledText):
            child.configure(bg='white', alpha=0.8)
        elif isinstance(child, ttk.Button):
            child.configure(style='Transparent.TButton')
        elif isinstance(child, ttk.Label):
            child.configure(style='Transparent.TLabel')

# 创透明样
style = ttk.Style()
style.configure('Transparent.TLabelframe', background='white', opacity=0.8)
style.configure('Transparent.TButton', background='white', opacity=0.8)
style.configure('Transparent.TLabel', background='white', opacity=0.8)

bg_label = tk.Label(root, image=bg_photo)
bg_label.place(x=0, y=0, relwidth=1, relheight=1)
bg_label.lower()  # 将背景置于底层
root.mainloop()