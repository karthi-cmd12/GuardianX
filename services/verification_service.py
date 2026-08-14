# ==========================================================
# GuardianX Verification Service
# Email & Mobile OTP Management
# ==========================================================


import random
import string
from datetime import datetime



# ==========================================================
# Generate OTP
# ==========================================================

def generate_otp():

    """
    Generates a 6 digit OTP
    """

    return ''.join(
        random.choices(
            string.digits,
            k=6
        )
    )



# ==========================================================
# Generate Email OTP
# ==========================================================

def create_email_otp(user):

    otp = generate_otp()

    user.email_otp = otp

    user.email_verified = False


    return otp



# ==========================================================
# Generate Mobile OTP
# ==========================================================

def create_mobile_otp(user):

    otp = generate_otp()

    user.mobile_otp = otp

    user.mobile_verified = False


    return otp



# ==========================================================
# Verify Email OTP
# ==========================================================

def verify_email_otp(user, otp):

    if user.email_otp == otp:

        user.email_verified = True

        user.email_otp = None


        return True


    return False



# ==========================================================
# Verify Mobile OTP
# ==========================================================

def verify_mobile_otp(user, otp):

    if user.mobile_otp == otp:

        user.mobile_verified = True

        user.mobile_otp = None


        return True


    return False



# ==========================================================
# Account Security Status
# ==========================================================

def verification_status(user):

    return {

        "email":

        user.email_verified,


        "mobile":

        user.mobile_verified,


        "fully_verified":

        user.email_verified and user.mobile_verified

    }