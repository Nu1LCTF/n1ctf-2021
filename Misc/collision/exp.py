import base64
from pwn import *
import numpy as np
import cv2
import torch
import torch.nn as nn
from hashlib import sha256
import torch.nn.functional as F
from torch.autograd import Variable
from itertools import product
from scipy.ndimage.filters import gaussian_filter
import argparse
import os
from PIL import Image

class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.conv1 = nn.Conv2d(1, 32, 3, 1)
        self.conv2 = nn.Conv2d(32, 64, 3, 1)
        self.dropout1 = nn.Dropout(0.25)
        self.dropout2 = nn.Dropout(0.5)
        self.fc1 = nn.Linear(9216, 128)
        self.fc2 = nn.Linear(128, 10)

    def forward(self, x):
        x = self.conv1(x)
        x = F.relu(x)
        x = self.conv2(x)
        x = F.relu(x)
        x = F.max_pool2d(x, 2)
        x = self.dropout1(x)
        x = torch.flatten(x, 1)
        x = self.fc1(x)
        return x

def load_model(path):
    model = Net()
    model.load_state_dict(torch.load(path, map_location="cpu"))
    return model.eval()

def save_image(arr, path):
    im = Image.fromarray(arr)
    im.save(path)

def get_hash_sim(adv_hash, std_hash):
    cnt = 0
    for i in range(len(adv_hash[0])):
        tmp1 = adv_hash[0][i] > 0
        tmp2 = std_hash[0][i] > 0
        if tmp1 != tmp2:
            cnt += 1
    return 1 - (cnt / len(adv_hash[0]))

def cal_hash_bits(out):
    return out

def hex_hash(hash_bits):
    x = hash_bits.detach().numpy()
    res = [str(int(i > 0)) for i in x[0]]
    return hex(int(''.join(res), 2))
model = load_model("convNet.pt")
target_image=torch.FloatTensor(np.load("mnist.npz")['test_images'][8583]).reshape(1,1,28,28)
target_out = model(target_image).detach()
target_nsgn=-torch.sign(target_out).detach()
image = torch.FloatTensor(np.load("mnist.npz")['test_images'][22]).reshape(1,1,28,28)
adv=Variable(image,requires_grad=True)
#optim=torch.optim.Adam([adv],lr=0.001)
loss_f=nn.L1Loss()
loss_l2=nn.MSELoss()
def attack():
    global adv
    # load model, seed, image
    max_sim = 0
    cnt = 0
    loss_cnt = 0
    losses = []
    lr=0.1
    RATIO=10
    itercnt=0
    best = 9999
    best_l0 = 9999
    best_l2 = 9999
    save_image(image.squeeze().detach().numpy(), 'origion.tiff')
    save_image(target_image.squeeze().detach().numpy(), 'target.tiff')
    for i in range(10000):
        adv_out=model(adv)
        l1l=loss_f(adv,image)*RATIO
        hashl=torch.sum(F.relu(target_nsgn*adv_out))
        l2l=loss_l2(adv,image)
        loss=l1l+hashl
        loss.backward()
        adv.requires_grad=False
        if hex_hash(adv_out)==hex_hash(target_out) and torch.sum(adv!=image).numpy() == 54 and l2l < 0.053:
            data = adv.squeeze().detach().numpy().astype("float32").tobytes()
            r = remote('43.129.202.109', '59101')
            context(log_level='debug')
            ALPHABET = string.ascii_letters + string.digits

            rec = r.recvline().decode()
            print(rec)
            rec = rec[rec.find('+')+1::]
            suffix = rec[rec.find('+')+1:rec.find(')')]
            digest = rec[rec.find('==')+3:-1]
            print(f"suffix: {suffix} \ndigest: {digest}")

            for i in product(ALPHABET, repeat=4):
                prefix = ''.join(i)
                guess = prefix + suffix
                if sha256(guess.encode()).hexdigest() == digest:
                    log.info(f"Find XXXX: {prefix}")
                    break
            r.sendline(prefix.encode())
            r.sendline(base64.b64encode(data))
            r.interactive()
            exit(0)

        # torch.nn.utils.clip_grad_norm_(adv.grad, 0.01)
        adv=adv-adv.grad*lr
        adv=adv.clamp(0,1)
        update = f"Iteration #{i}: l1={l1l} l2loss={l2l} hashloss={hashl}"
        print(update)
        print(hex_hash(adv_out))
        print(hex_hash(target_out))
        print("diffcount",torch.sum(torch.abs(adv-image)>0.005))
        print(f"l0 loss: {torch.sum(adv!=image)}")

        print("best ", best)
        print(f"best_l0: {best_l0}")
        print(f"best_l2: {best_l2}")
        if hex_hash(adv_out)==hex_hash(target_out):
            best=min(best,torch.sum(torch.abs(adv-image)>0.005).numpy())
            best_l0=min(best_l0,torch.sum(adv!=image).numpy())
            best_l2 = min(best_l2, l2l)
            itercnt+=1
            #clip slight modify
            mask=(torch.abs(adv-image)<np.clip(0.02+0.04*itercnt,0.02,0.4)).type(torch.FloatTensor)
            adv=adv*(1-mask)+image*mask
        adv.requires_grad = True
        #    save_image(adv.squeeze().detach().numpy(), 'collision_pic.tiff')
        #    return 1
    save_image(adv.squeeze().detach().numpy(), 'collision_pic.tiff')

if __name__ == "__main__":
    attack()
