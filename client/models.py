from email.policy import default
from typing import Optional , List
from sqlmodel import Field, SQLModel, create_engine, Relationship


class Contact(SQLModel, table=True):
    id: Optional[int] = Field(default= None, primary_key=True, nullable= False)
    name: str = Field()
    email: str = Field()
    public_key: str = Field(nullable= True)
    preshared_key: str = Field(nullable = True)
    # messages: List["Message"] = Relationship(back_populates = "contact")



class Message(SQLModel, table= True):
    id: Optional[int] = Field(default=None, primary_key = True, nullable= False)
    
    received : int = Field(default=0)
    sending_time: str = Field()
    message: str = Field()
    contact_id:Optional[int] = Field(default= None, foreign_key= "contact.id")
    contact: Optional[Contact] = Relationship(back_populates = "messages")

class Client(SQLModel, table= True):
    id: Optional[int] = Field(default=None, primary_key = True, nullable= False)
    pk: str = Field()
    sk: str = Field()
    


sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

engine = create_engine(sqlite_url, echo=True)



def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

create_db_and_tables()
    
        