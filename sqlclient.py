# from sqlmodel import SQLModel, create_engine\
import pickle
import rsa
import base64

# sqlite_file_name = "database.db"
# sqlite_url = f"sqlite:///{sqlite_file_name}"

# engine = create_engine(sqlite_url)



# def create_db_and_tables():
#     SQLModel.metadata.create_all(engine)
    
    
def getServerKeys():
    import requests

    headers = {
        'accept': 'application/json',
    }

    response = requests.get('http://127.0.0.1:8000/getserversk', headers=headers)
    if response.status_code == 200:
        res = response.json()
        ser_pubK = pickle.loads(base64.b64decode(res['Server_public_K']))
        return ser_pubK
        
        

    