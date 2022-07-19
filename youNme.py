from signal_protocol import curve, identity_key, state, storage
from fastapi import FastAPI, File, UploadFile, HTTPException, status,Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise import fields
from tortoise.fields import relational
from tortoise.models import Model
from tortoise.contrib.fastapi import register_tortoise 
from tortoise.contrib.pydantic import pydantic_model_creator
from pydantic import BaseModel
import jwt



server_identity_keys = identity_key.IdentityKeyPair.generate()


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




class Server:
    def __init__(self, pk, sk):
        self.pk = pk
        self.sk = sk


server = Server()

class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=50, unique=True)
    password_hash = fields.CharField(max_length=128)
    name = fields.CharField(max_length=50)
    lName = fields.CharField(max_length=50)
    phone_number = fields.CharField(max_length=50, unique = True)

    public_key = fields.CharField(max_length=530, null = True)
     #CharField(max_length= 1024, null= True)     #CharField(max_length= 1024, null= True)



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




@app.get('/getserversk')
async def getServerPublicKey():
    server_SK = await server.sk
    server_SK = server_SK
    return {"Server_SK": server_SK}



@app.post('/register', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    print( user.username ,user.password_hash)

    user_ob = User(username=user.username, password_hash=hashlib.sha256(user.password_hash.strip().encode('utf_8')).hexdigest(), name = user.name, lName=user.lName, phone_number=user.phone_number)
    await user_ob.save()
    
    return await User_Pydantic.from_tortoise_orm(user_ob)


    