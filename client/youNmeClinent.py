import json
import requests

from signal_protocol import curve, identity_key, state, storage
from fastapi import FastAPI, File, UploadFile, HTTPException, status,Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise import fields
from tortoise.fields import relational
from tortoise.models import Model
from tortoise.contrib.fastapi import register_tortoise 
from tortoise.contrib.pydantic import pydantic_model_creator



client_identity_keys = identity_key.IdentityKeyPair.generate()





class Contact(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=50, unique=True)
    public_key = fields.CharField(max_length=514)
    preshared_key = fields.CharField(max_length=514)
   
    
   
     #CharField(max_length= 1024, null= True)     #CharField(max_length= 1024, null= True)



class Message(Model):
    id = fields.IntField(pk=True)
    sender = relational.ForeignKeyField("models.User", "user_id",null= True, on_delete=fields.SET_NULL)
    time = fields.TimeField()
    message = fields.CharField(max_length= 1024)
    

    message = fields.CharField(max_length=1024)
    
     #CharField(max_length= 1024, null= True)     #CharField(max_length= 1024, null= True)

from tortoise import Tortoise, run_async
import asyncio 

async def init():
    # Here we create a SQLite DB using file "db.sqlite3"
    #  also specify the app name of "models"
    #  which contain models from "app.models"
    await Tortoise.init(
        db_url='sqlite://db.sqlite3',
        modules={'models': ['youNmeClinent']}
    )
    # Generate the schema
    await Tortoise.generate_schemas()

# run_async is a helper function to run simple async Tortoise scripts.
run_async(init())


