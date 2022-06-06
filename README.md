# brop_tools

一个ctf中pwn方向的brop题目dump小工具，由于brop中dump文件这一部分比较模板化，所有写一个工具来帮助各位ctfer更快的完成攻击。

## 环境配置

需要先安装pyqt5的库和pwntools的库

```shell
sudo apt update
sudo apt install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential -y
python3 -m pip install --upgrade pip
pip3 install --upgrade pwntools
pip  install sip
pip install PyQt5
pip install PyQt5-tools
```

## 使用方式

（目前只实现了brop中64位的puts函数的攻击，考研中时间比较紧迫，日后可能会实现所有的blind pwn）

使用方式

```shell
cd puts
python brop.py
```

支持选择爆破起始点，只需要在要计算的位置填写爆破起始点即可，爆破完成后后自动填补
**注意：最后的哪个选项是为了dunp文件的，一定要选择程序最开始打印的几个字符**
