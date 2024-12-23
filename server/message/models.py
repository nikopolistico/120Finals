from django.db import models


# Create your models here.
class Message(models.Model):
    content = models.TextField()  # Encrypts the content field
    sender = models.CharField(max_length=50)
    payment =  models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Message from {self.sender} : {self.content[:50] : {self.payment}}'
    

class PaymentConfirmation(models.Model):
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.content