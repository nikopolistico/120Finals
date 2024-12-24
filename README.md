Introduction
This project demonstrates secure communication between two Django projects running on different ports. The communication involves encryption at the client middleware level using the Fernet symmetric encryption method and decryption on the server-side middleware. Additionally, CORS headers are configured to strictly control which ports or addresses can communicate.

FEATURES
Two separate Django projects communicating seamlessly
Middleware encryption and decryption for secure data exchange using Fernet
Integration with Django Rest Framework (DRF)
Strict CORS configuration to enhance security
Scalable and easy-to-integrate architecture

GUIDELINES
1. Install virtualenv to create isolated environments for the projects.
2. Create a folder named virtual and navigate to it.
3. Create two Django projects named client and server using django-admin startproject.
4. Within both projects, create an app named message using python manage.py startapp message.
5. Create a templates folder in both projects for templating purposes.
6. Install the cryptography library for Fernet symmetric encryption by running pip install cryptography.
7. Create custom middleware in both client and server projects to handle encryption and decryption of messages.
8. Install django-cors-headers by running pip install django-cors-headers and configure it in settings.py to strictly control allowed origins and ports.
9. Write the necessary views and handlers in the message app to enable communication between the two projects.
10. Test the setup to ensure secure encrypted communication is established between client and server.


GROUP 1 MEMBERS:
BERNIE CHERRY RANTE
NIKO POLISTICO
MARK AHRON TAGLUCOP
DAVE JASON SALTE
LAURENCE JAY PEREZ

For more information: https://nikopolistico.github.io/doc/?fbclid=IwY2xjawHW1zpleHRuA2FlbQIxMAABHQbCxbLVdeZAApIVb2CLbtJyhJHO-qMmhWBHdDypvmw4N0Ce4EdRyh3FSg_aem_VadO80fvqxDCXJ895xMksg#contributors
