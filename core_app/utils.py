from django.core.mail import EmailMessage
from rest_framework_simplejwt.tokens import RefreshToken
import threading

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


 
class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email='<EMAIL_ADDRESS>',
            to=[data['to_email']]
        )
        email.send()



class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()

def send_email(subject, body, to, from_email='sunilkunkekar1@gmail'):
    email = EmailMessage(subject, body, from_email, [to])
    EmailThread(email).start()

