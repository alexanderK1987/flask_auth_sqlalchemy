from app import (ma)
import models.UserModel

class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = models.UserModel.User
        include_fk = True


