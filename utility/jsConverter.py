import js2py
import shutil

js2py.translate_file('tp_link_encryption.js', 'tp_link_encryption.py') 
shutil.move("tp_link_encryption.py", "../tp_connected/tp_link_encryption.py")