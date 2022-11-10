# from sqlmodel import SQLModel, create_engine\
import pickle
import rsa
import base64
import requests

# sqlite_file_name = "database.db"
# sqlite_url = f"sqlite:///{sqlite_file_name}"
# db
# engine = create_engine(sqlite_url)



# def create_db_and_tables():
#     SQLModel.metadata.create_all(engine)
    
    
def getServerKeys():
    

    headers = {
        'accept': 'application/json',
    }

    response = requests.get('http://127.0.0.1:8000/getserversk', headers=headers)
    if response.status_code == 200:
        res = response.json()
        ser_pubK = pickle.loads(base64.b64decode(res['Server_public_K']))
        return ser_pubK
        
print(getServerKeys())
        
def sendMessage(message, to):
    headers = {
    'accept': 'application/json',
    'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NCwidXNlcm5hbWUiOiJzdHJpbmcxIiwicGFzc3dvcmRfaGFzaCI6IjQ3MzI4N2Y4Mjk4ZGJhNzE2M2E4OTc5MDg5NThmN2MwZWFlNzMzZTI1ZDJlMDI3OTkyZWEyZWRjOWJlZDJmYTgiLCJuYW1lIjoic3RyaW5nMSIsImxOYW1lIjoic3RyaW5nIiwicGhvbmVfbnVtYmVyIjoic3RyaW5nMSIsInB1YmxpY19rZXkiOm51bGx9.gce0Sp5JmdTCNdU7OreZBnkiYSES0ZtSLJFK1qRmWJw',
    # Already added when you pass json= but not when you pass data=
    # 'Content-Type': 'application/json',
    }

    json_data = {
        
        'message_con': base64.b64encode(rsa.encrypt(pickle.dumps(message), getServerKeys())).decode(),
        'to': base64.b64encode(rsa.encrypt(pickle.dumps(to), getServerKeys())).decode(),
    }

    response = requests.post('http://127.0.0.1:8000/message', headers=headers, json=json_data)
    
    
sendMessage("Encrypted", "string")
        

    
