from blinker import receiver_connected
# from signal_protocol import curve, identity_key, state, storage
from fastapi import FastAPI, File, UploadFile, HTTPException, status,Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise import fields
from tortoise.fields import relational
from tortoise.models import Model
from tortoise.contrib.fastapi import register_tortoise 
from tortoise.contrib.pydantic import pydantic_model_creator
from pydantic import BaseModel
import jwt
import hashlib
import rsa
import pickle



# key_pair_generation
# server_identity_keys = identity_key.IdentityKeyPair.generate()


JWT_SECRET = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.c3N3b3JkX2hhc2giOiJlYzE4NTc5NWQ3MTFkM2NkNmI1NeyJpZCI6MiwidXNlcm5hbWUiOiJSOCIsInBhjYzZDNhNTQ2NTFjNzIwYThmMzExMW"



oa2 = OAuth2PasswordBearer(tokenUrl='token')


app = FastAPI()



async def authenticate_user(username: str, password: str):
    user = await User.get(username= username) 
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user

async def get_current_user(token: str=Depends(oa2)):
    
    try:
        
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await User.get(id = payload.get("id"))

    except:
        raise HTTPException(status_code = 401, detail="Invalid Username or Password!")


    return await User_Pydantic.from_tortoise_orm(user)




class MessageSent(BaseModel):
    message_con : str
    to : str



class Userr(BaseModel):
    name: str
    lastname: str
    email: str
    password: str






class Server:
    def __init__(self, pk, sk):
        self.pk = pk
        self.sk = sk

try:
    with open("priv.k", "rb") as f:
        priv  = f.read()
    priv_key = pickle.loads(priv)
    with open("pub.k", "rb") as f:
        pub  = f.read()
        print(type(pub))
    pub_key = pickle.loads(pub)
    print(type(pub_key))
# priv_key = rsa.PrivateKey.load_pkcs1(priv)
    # pub_key = rsa.PublicKey.load_pkcs1(priv)
    
    print("Read it, ") 
    print(priv_key)
    print(pub_key)
            
        
        

except:
    pub_key , priv_key= rsa.newkeys(512)
    print("Printed It",  priv_key)
    print( pub_key)
    with open("priv.k", "wb") as f:
        pickle.dump(priv_key, f)
    with open("pub.k", "wb") as f:
        pickle.dump(pub_key, f)


server = Server(priv_key,pub_key)

class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=50, unique=True)
    password_hash = fields.CharField(max_length=128)
    name = fields.CharField(max_length=50)
    lName = fields.CharField(max_length=50)
    phone_number = fields.CharField(max_length=50, unique = True)

    public_key = fields.CharField(max_length=530, null = True)
     #CharField(max_length= 1024, null= True)     #CharField(max_length= 1024, null= True)
     
    async def get_user(self, username):
        return self.get(username=username)

    def verify_password(self, password):
        return True



class Message(Model):
    id = fields.IntField(pk=True)
    sender = relational.ForeignKeyField("models.User", "user_id",null= True, on_delete=fields.SET_NULL)
    receiver = relational.ForeignKeyField("models.User", "user_username",null= False, on_delete=fields.CASCADE)
    

    message = fields.CharField(max_length=1024)
    delivered = fields.IntField(default=0)
    
    #CharField(max_length= 1024, null= True)     #CharField(max_length= 1024, null= True)





class Userr(BaseModel):
    name: str
    lastname: str
    phone_number: str
    password: str
    pub_key: str


register_tortoise(app, 
db_url="sqlite://db.sqlite3",
modules={'models':['youNme']},
generate_schemas= True,
add_exception_handlers=True
)

User_Pydantic = pydantic_model_creator(User, name='User')
UserIn_Pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly=True)


import base64

@app.get('/getserversk')
async def getServerPublicKey():
    server_SK = server.sk
    server_SK = server_SK
    string = base64.b64encode(pickle.dumps(server_SK)).decode()
    return {"Server_public_K": string}



@app.post('/register', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    print( user.username ,user.password_hash)

    user_ob = User(username=user.username, password_hash=hashlib.sha256(user.password_hash.strip().encode('utf_8')).hexdigest(), name = user.name, lName=user.lName, phone_number=user.phone_number)
    await user_ob.save()
    
    return await User_Pydantic.from_tortoise_orm(user_ob)

@app.post('/token')
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    print(form_data.username, form_data.password)
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code = 401, detail="Invalid Username or Password!")
   

    user_obj = await User_Pydantic.from_tortoise_orm(user)
    # print(user_obj.password_hash)
    # print(hashlib.sha256(form_data.password.encode('utf_8')).hexdigest())
    
    if user_obj.password_hash != hashlib.sha256(form_data.password.encode('utf_8')).hexdigest():
        raise HTTPException(status_code = 401, detail="Invalid Username or Password!")
    ob_dict = user_obj.dict()
    print(ob_dict)
    token = jwt.encode(ob_dict, JWT_SECRET)
    print(token)

    return {"access_token": token, 'token_type':  'bearer'}



@app.post('/message')
async def message(message: MessageSent, user: User_Pydantic= Depends(get_current_user)):
    
    
    message_con = pickle.loads(rsa.decrypt(base64.b64decode(message.message_con), server.pk))
    receiver = pickle.loads(rsa.decrypt(base64.b64decode(message.to), server.pk))
    print(receiver)
    

    receiver = await User.get(username= receiver)
    
    
    
    sender = await User.get(username = user.username)
    print("here here")

    message = await Message(sender = sender, receiver = receiver , message = message_con)
    
    await message.save()
    idn = message.id
    
    
    
    another = await Message.get(id= idn)
    
    print("here here 3")
 
    return another 
    
    
@app.post('/loadmessage')
async def message(message: MessageSent, user: User_Pydantic= Depends(get_current_user)):
    messages = await Message.filter(receiver = user.id, delivered= 0)
    for message in messages:
        message.delivered = 1
        await message.save()
        print(message.sender_id)
        try:
            message.sender_id = await User.get(id = message.sender_id)
        except:
            pass
    return messages
    
 
    
