from django.contrib import admin

# Register your models here.
from . models import OTP, PendingUser
admin.site.register(OTP)
admin.site.register(PendingUser) 