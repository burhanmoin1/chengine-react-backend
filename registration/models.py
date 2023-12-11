from django_mongoengine import Document, fields

class User(Document):
    email = fields.EmailField(blank=False, unique=True)
    password = fields.StringField(blank=False)
    verified = fields.BooleanField(default=False)
    activation_token = fields.StringField(blank=True)
    password_reset_token = fields.StringField(blank=True)
        
class Guitarist(Document):
    guitar_brand = fields.StringField(max_length=255)
    guitar_model = fields.StringField(blank=False, max_length=255)
    guitar_color = fields.StringField(max_length=500)
    STRING_CHOICES = (
        ('6', '6'),
        ('7', '7'),
        ('8', '8')
    )
    number_of_strings = fields.StringField(max_length=20, choices=STRING_CHOICES)
