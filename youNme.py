from signal_protocol import curve, identity_key, state, storage
from fastapi import FastAPI, File, UploadFile, HTTPException, status,Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise import fields
from tortoise.fields import relational
from tortoise.models import Model
from tortoise.contrib.fastapi import register_tortoise 
from tortoise.contrib.pydantic import pydantic_model_creator



server_identity_keys = identity_key.IdentityKeyPair.generate()


app = FastAPI()




class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=50, unique=True)
    password_hash = fields.CharField(max_length=128)
    name = fields.CharField(max_length=50)
    lName = fields.CharField(max_length=50)
    email = fields.CharField(max_length=50)
    
    public_key = fields.CharField(max_length=530, null = True)
     #CharField(max_length= 1024, null= True)     #CharField(max_length= 1024, null= True)



class Message(Model):
    id = fields.IntField(pk=True)
    sender = relational.ForeignKeyField("models.User", "user_id",null= True, on_delete=fields.SET_NULL)
    receiver = relational.ForeignKeyField("models.User", "user_id",null= False, on_delete=fields.CASCADE)
    

    message = fields.CharField(max_length=1024)
    
     #CharField(max_length= 1024, null= True)     #CharField(max_length= 1024, null= True)




@app.get('/getserverpk')
async def getServerPublicKey():
    return {"token": "token"}


    