# -*- coding: utf-8 -*-
"""
Created on Wed Apr  4 13:54:18 2018

@author: Sherlock Holmes
"""

from tkinter import *
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
import base64
import os

# RSA公钥、私钥生成函数
def getRSAKey(passwordPath1, passwordPath2):
    # 生成公钥、私钥  
    key = RSA.generate(2048)
    publicKey = key.publickey().exportKey()
    privateKey = key.exportKey()
    try:
        passwordFile1 = open(passwordPath1, mode = 'wb')
    except IOError:
        # 口令文件路径错误
        return 1
    try:
        passwordFile2 = open(passwordPath2, mode = 'wb')
    except IOError:
        # 密文文件路径错误
        return 2
    passwordFile1.write(publicKey)
    passwordFile2.write(privateKey)
    passwordFile1.close()
    passwordFile2.close()
    return 0

# RSA加密
def RSAEncrypt(text, publicKey):
    # 导入读取到的公钥
    rsakey = RSA.importKey(publicKey)
    # 生成对象
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    # 通过生成的对象加密message明文（python3中加密的数据必须是bytes类型的数据，不能是str类型的数据）
    ciphertext = base64.b64encode(cipher.encrypt(text))
    return ciphertext

# RSA解密  
def RSADecrypt(text, privateKey):  
    # 导入读取到的私钥
    rsakey = RSA.importKey(privateKey)
    # 生成对象
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    # 将密文解密成明文（返回的是一个bytes类型数据，需要自己转换成str）
    result = cipher.decrypt(base64.b64decode(text), "ERROR")
    return result


# 通过文件输入明文和口令，将结果输出到一个文件
def EncryptRSAFile(textPath, passwordPath, cipherPath):
    try:
        textFile = open(textPath, mode = 'rb')
    except IOError:
        # 明文文件路径错误
        return 1
    try:
        passwordFile = open(passwordPath, mode = 'rb')
    except IOError:
        # 口令文件路径错误
        return 2
    try:
        cipherFile = open(cipherPath, mode = 'wb')
    except IOError:
        # 密文文件路径错误
        return 3
    cipherFile.write(RSAEncrypt(textFile.read(), passwordFile.read()))
    textFile.close()
    passwordFile.close()
    cipherFile.close()
    return 0

# 通过文件输入密文和口令，将恢复的明文输出到一个文件
def DecryptRSAFile(cipherPath, passwordPath, textPath):
    try:
        cipherFile = open(cipherPath, mode = 'rb')
    except IOError:
        # 密文文件路径错误
        return 1
    try:
        passwordFile = open(passwordPath, mode = 'rb')
    except IOError:
        # 口令文件路径错误
        return 2
    try:
        textFile = open(textPath, mode = 'wb')
    except IOError:
        # 明文文件路径错误
        return 3    
    textFile.write(RSADecrypt(cipherFile.read(), passwordFile.read()))
    cipherFile.close()
    passwordFile.close()
    textFile.close()
    return 0

# 打开窗口中要插入的图片文件
tmp = Tk()
img0 = PhotoImage(file='RSA.png')
img1 = PhotoImage(file='encrypt.png')
img2 = PhotoImage(file='decrypt.png')


# 程序图形化窗体类
class GraphicInterface(Frame):
    # 构造函数
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.pack()
        self.createWidgets()
        
    # 创建窗体的函数
    def createWidgets(self):
        # 使用ttk中的Notebook作为窗体的模板
        self.nb = ttk.Notebook()
        # 窗体标题
        self.master.title('RSA加密解密程序V1.0')
        # 设置窗体的几何大小
        self.master.geometry('800x400')
        # 设置窗体的左上角的图标
        self.master.iconbitmap('rsa.ico')
        
        # 初始化明文、密文、加密密钥、解密密钥文件路径为空（便于后面的异常处理）
        self.filename3 = ""
        self.filename4 = ""
        self.filename5 = ""
        self.filename6 = ""
        
        # 向Notebook窗体中添加组件
        
        # “生成RSA公钥与私钥”选项卡
        self.page0 = ttk.Frame(self.nb)
        # “生成RSA公钥与私钥”页图片
        self.image0 = Label(self.page0, image=img0)
        self.image0.pack(side=LEFT, fill=Y, padx=10, pady=10)
        # 提示文本
        self.label1 = Label(self.page0, text="请选择要生成RSA公钥与私钥文本位置")
        self.label1.pack(side=TOP, fill=BOTH, padx=5, pady=5)
        self.label2 = Label(self.page0, text="公钥文本路径：")
        self.label2.pack(padx=5, pady=5)
        # 显示公钥文件路径的文本
        self.txt1 = Text(self.page0, height=1, width=50)
        self.txt1.pack(padx=5, pady=5)
        # 选择文件的按钮
        self.fileChooser1 = Button(self.page0, text='选择文件', command=self.selectPublicKey)
        self.fileChooser1.pack(padx=5, pady=5)
        # 提示文本
        self.label3 = Label(self.page0, text="私钥文本路径：")
        self.label3.pack(padx=5, pady=5)
        # 显示私钥文件路径的文本
        self.txt2 = Text(self.page0, height=1, width=50)
        self.txt2.pack(padx=5, pady=5)
        # 选择文件的按钮
        self.fileChooser2 = Button(self.page0, text='选择文件', command=self.selectPrivateKey)
        self.fileChooser2.pack(padx=5, pady=5)
        # 开始加密按钮
        self.alertButton1 = Button(self.page0, text='开始生成', command=self.getKey)
        self.alertButton1.pack(side=BOTTOM, padx=5, pady=10)
        
        # “RSA加密”选项卡
        self.page1 = ttk.Frame(self.nb)
        # “RSA加密”页图片
        self.image1 = Label(self.page1, image=img1)
        self.image1.pack(side=LEFT, fill=Y, padx=10, pady=10)
        # 提示文本
        self.label4 = Label(self.page1, text="请选择要加密的文本")
        self.label4.pack(side=TOP, fill=BOTH, padx=5, pady=5)
        self.label5 = Label(self.page1, text="明文文本路径：")
        self.label5.pack(padx=5, pady=5)
        # 显示明文文件路径的文本
        self.txt3 = Text(self.page1, height=1, width=50)
        self.txt3.pack(padx=5, pady=5)
        # 选择文件的按钮
        self.fileChooser3 = Button(self.page1, text='选择文件', command=self.selectPlainText)
        self.fileChooser3.pack(padx=5, pady=5)
        # 提示文本
        self.label6 = Label(self.page1, text="密钥文本路径：")
        self.label6.pack(padx=5, pady=5)
        # 显示加密密钥文件路径的文本
        self.txt4 = Text(self.page1, height=1, width=50)
        self.txt4.pack(padx=5, pady=5)
        # 选择文件的按钮
        self.fileChooser4 = Button(self.page1, text='选择文件', command=self.selectPassword1)
        self.fileChooser4.pack(padx=5, pady=5)
        # 开始加密按钮
        self.alertButton2 = Button(self.page1, text='开始加密', command=self.encrypt)
        self.alertButton2.pack(side=BOTTOM, padx=5, pady=10)
        
        # “RSA解密”选项卡
        self.page2 = ttk.Frame(self.nb)
        # “RSA解密”页图片
        self.image2 = Label(self.page2, image=img2)
        self.image2.pack(side=LEFT, fill=Y, padx=10, pady=10)
        # 提示文本
        self.label7 = Label(self.page2, text="请选择要解密的文本")
        self.label7.pack(side=TOP, fill=BOTH, padx=5, pady=5)
        self.label8 = Label(self.page2, text="密文文本路径：")
        self.label8.pack(padx=5, pady=5)
        # 显示密文文件路径的文本
        self.txt5 = Text(self.page2, height=1, width=60)
        self.txt5.pack(padx=5, pady=5)
        # 选择文件的按钮
        self.fileChooser5 = Button(self.page2, text='选择文件', command=self.selectCipherText)
        self.fileChooser5.pack(padx=5, pady=5)
        # 提示文本
        self.label9 = Label(self.page2, text="密钥文本路径：")
        self.label9.pack(padx=5, pady=5)
        # 显示解密密钥文件路径的文本
        self.txt6 = Text(self.page2, height=1, width=60)
        self.txt6.pack(padx=5, pady=5)
        # 选择文件的按钮
        self.fileChooser6 = Button(self.page2, text='选择文件', command=self.selectPassword2)
        self.fileChooser6.pack(padx=5, pady=5)
        # 开始解密按钮
        self.alertButton3 = Button(self.page2, text='开始解密', command=self.decrypt)
        self.alertButton3.pack(side=BOTTOM, padx=5, pady=10)
        
        # 将三个选项卡页面加入窗体
        self.nb.add(self.page0, text='生成RSA公钥与私钥')
        self.nb.add(self.page1, text='RSA加密')
        self.nb.add(self.page2, text='RSA解密')
        self.nb.pack(expand=1, fill="both")
    
    # 选择写入公钥文件函数（限定txt文本）
    def selectPublicKey(self):
        self.filename1 = tk.filedialog.askopenfilename(filetypes=[("文本格式","txt")])
        self.txt1.delete(1.0, END)
        self.txt1.insert(1.0, self.filename1)
    
    # 选择写入私钥文件函数（限定txt文本）
    def selectPrivateKey(self):
        self.filename2 = tk.filedialog.askopenfilename(filetypes=[("文本格式","txt")])
        self.txt2.delete(1.0, END)
        self.txt2.insert(1.0, self.filename2)
    
    # 选择明文文件函数（限定txt文本）
    def selectPlainText(self):
        self.filename3 = tk.filedialog.askopenfilename(filetypes=[("文本格式","txt")])
        self.txt3.delete(1.0, END)
        self.txt3.insert(1.0, self.filename3)
    
    # 选择加密密钥文件函数（限定txt文本）
    def selectPassword1(self):
        self.filename4 = tk.filedialog.askopenfilename(filetypes=[("文本格式","txt")])
        self.txt4.delete(1.0, END)
        self.txt4.insert(1.0, self.filename4)
    
    # 选择密文文件函数（限定txt文本）
    def selectCipherText(self):
        self.filename5 = tk.filedialog.askopenfilename(filetypes=[("文本格式","txt")])
        self.txt5.delete(1.0, END)
        self.txt5.insert(1.0, self.filename5)
    
    # 选择解密密钥文件函数（限定txt文本）
    def selectPassword2(self):
        self.filename6 = tk.filedialog.askopenfilename(filetypes=[("文本格式","txt")])
        self.txt6.delete(1.0, END)
        self.txt6.insert(1.0, self.filename6)

    # 生成RSA公钥、私钥函数
    def getKey(self):
        # 公钥文本路径为空，报错
        if self.filename1 == "":
            messagebox.showinfo('Message', '您还未选择公钥文本！')
        # 私钥文本路径为空，报错
        elif self.filename2 == "":
            messagebox.showinfo('Message', '您还未选择私钥文本！')
        else:
            getRSAKey(self.filename1, self.filename2)
            messagebox.showinfo('Message', 'Success generate RSA key file: ' + self.filename1 + ' (Public Key File) & ' + self.filename2 + ' (Private Key File)!')

    # 加密函数（含异常处理）
    def encrypt(self):
        # 明文文本路径为空，报错
        if self.filename3 == "":
            messagebox.showinfo('Message', '您还未选择明文文本！')
        # 加密密钥文本路径为空，报错
        elif self.filename4 == "":
            messagebox.showinfo('Message', '您还未选择密钥文本！')
        else:
            EncryptRSAFile(self.filename3, self.filename4, "ciphertext.txt")
            messagebox.showinfo('Message', 'Success encrypt plaintext file: ' + self.filename3 + ' using password file ' + self.filename4 + ' !')

    # 解密函数（含异常处理）        
    def decrypt(self):
        # 密文文本路径为空，报错
        if self.filename5 == "":
            messagebox.showinfo('Message', '您还未选择密文文本！')
        # 解密密钥文本路径为空，报错
        elif self.filename6 == "":
            messagebox.showinfo('Message', '您还未选择密钥文本！')
        else:
            # 异常处理
            try:
                DecryptRSAFile(self.filename5, self.filename6, "result.txt")
            # 抛出异常，得到异常的信息
            except TypeError as e:
                # 参与解密的不是私钥
                if str(e) == "No private key":
                    messagebox.showinfo('Message', '解密的密钥不是私钥！')
                # 参与解密的私钥不正确
                elif str(e) == "a bytes-like object is required, not 'str'":
                    messagebox.showinfo('Message', '私钥不是正确的解密私钥！')
                # 其他
                else:
                    messagebox.showinfo('Message', '程序解密功能出现异常！')
            else:
                messagebox.showinfo('Message', 'Success decrypt plaintext file: ' + self.filename5 + ' using password file ' + self.filename6 + ' !')
                

# 实例化窗体类
gui = GraphicInterface()
# 主消息循环:
gui.mainloop()