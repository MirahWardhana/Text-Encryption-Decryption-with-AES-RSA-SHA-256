from tkinter import*
import time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib

root= Tk()
root.title("Enkripsi dan Dekripsi Teks Algoritma AES, RSA, dan SHA-256")
root.geometry("450x250")
root.configure(bg='white')


def AES_algorithm():
    key = b'C&F)H@McQfTjWnZr'
    cipher = AES.new(key, AES.MODE_EAX)
    data = text_input.get().encode()
    nonce = cipher.nonce
    
    # Encrypt message
    start_time = time.time()
    encrypted_message = cipher.encrypt(data)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    end_time = time.time()
    textBox=Entry(root,width=20)
    textBox.insert(END, encrypted_message)
    textBox.grid(row=5,column=0)
    textBox2=Entry(root,width=20)
    textBox2.grid(row=7,column=0)
    textBox2.insert(END, end_time - start_time)
    
    # Decrypt message
    start_time = time.time()
    decrypted_message = cipher.decrypt(encrypted_message) 
    end_time = time.time()
    textBox3=Entry(root,width=20)
    textBox3.grid(row=9,column=0)
    textBox3.insert(END, decrypted_message)
    textBox4=Entry(root,width=20)
    textBox4.grid(row=11,column=0)
    textBox4.insert(END, end_time - start_time)

def RSA_algorithm():
    data = text_input.get().encode()
    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    cipher = PKCS1_OAEP.new(key)
    
    # Encrypt message
    start_time = time.time()
    encrypted_message = cipher.encrypt(data)
    end_time = time.time()
    textBox=Entry(root,width=20)
    textBox.insert(END, encrypted_message)
    textBox.grid(row=5,column=1)
    textBox2=Entry(root,width=20)
    textBox2.grid(row=7,column=1)
    textBox2.insert(END, end_time - start_time)
    
    # Decrypt message
    start_time = time.time()
    decrypted_message = cipher.decrypt(encrypted_message)
    end_time = time.time()
    textBox3=Entry(root, width=20)
    textBox3.insert(END, decrypted_message)
    textBox3.grid(row=9,column=1)
    textBox4=Entry(root,width=20)
    textBox4.insert(END, end_time - start_time)
    textBox4.grid(row=11,column=1)
    
def SHA256_algorithm():
    data = text_input.get()
    start_time = time.time()
    hash_object = hashlib.sha256(data.encode())
    hex_digest = hash_object.hexdigest()
    end_time = time.time()
    
    # Encrypt message
    start_time = time.time()
    hex_digest = hash_object.hexdigest()
    end_time = time.time()
    textBox1=Entry(root, width=20)
    textBox1.insert(END, hex_digest)
    textBox1.grid(row=5,column=2)
    textBox2=Entry(root, width=20)
    textBox2.insert(END, end_time - start_time)
    textBox2.grid(row=7,column=2)
    
    # Decrypt message
    start_time = time.time()
    decrypted_message = "null"
    end_time = time.time()
    textBox3=Entry(root, width=20)
    textBox3.insert(END, decrypted_message)
    textBox3.grid(row=9,column=2)
    textBox4=Entry(root,width=20)
    textBox4.insert(END, end_time - start_time)
    textBox4.grid(row=11,column=2)
    

text_input=Entry(root, width=70)
text_input.grid(row=1,column=0, columnspan=3)

buttonCommit=Button(root, height=1, width=20, text="AES Algorithm", command=AES_algorithm)
buttonCommit.grid(row=3,column=0)
buttonCommit=Button(root, height=1, width=20, text="RSA Algorithm", command=RSA_algorithm)
buttonCommit.grid(row=3,column=1)
buttonCommit=Button(root, height=1, width=20, text="SHA-256 Algorithm", command=SHA256_algorithm)
buttonCommit.grid(row=3,column=2)


label= Label(root, text="Plain text", font= ('Times 10 bold'))
label.grid(row=0,column=0, columnspan=3)

label= Label(root, text="Encryption Result", font= ('Times 10 bold'))
label.grid(row=4,column=0, columnspan=3)

label= Label(root, text="Encryption Time Complexity (in second)", font= ('Times 10 bold'))
label.grid(row=6,column=0, columnspan=3)

label= Label(root, text="Decryption Result", font= ('Times 10 bold'))
label.grid(row=8,column=0, columnspan=3)

label= Label(root, text="Decryption Time Complexity (in second)", font= ('Times 10 bold'))
label.grid(row=10,column=0, columnspan=3)

root.mainloop()