import base64
import os
import re

from flask_dance.contrib.google import google
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build



CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "")




def get_gmail_service():

    if not google.authorized:

        print("Gmail not authorized")

        return None



    token = google.token



    credentials = Credentials(

        token=token["access_token"],

        refresh_token=token.get("refresh_token"),

        token_uri="https://oauth2.googleapis.com/token",

        client_id=CLIENT_ID,

        client_secret=CLIENT_SECRET

    )



    service = build(

        "gmail",

        "v1",

        credentials=credentials

    )



    return service





# =====================================
# Recursive Gmail Part Scanner
# =====================================

def process_parts(parts, body_data, attachments):


    for part in parts:


        filename = part.get(
            "filename"
        )


        # Attachment Detection

        if filename:


            attachments.append({

                "name": filename,

                "type": part.get(
                    "mimeType",
                    "unknown"
                )

            })



        mime_type = part.get(
            "mimeType",
            ""
        )



        data = part.get(
            "body",
            {}
        ).get(
            "data"
        )



        # Extract text body

        if data and mime_type in [

            "text/plain",
            "text/html"

        ]:


            try:

                decoded = base64.urlsafe_b64decode(
                    data
                ).decode(
                    "utf-8",
                    errors="ignore"
                )


                body_data.append(
                    decoded
                )


            except Exception:

                pass




        # Check nested parts

        if part.get("parts"):

            process_parts(

                part["parts"],

                body_data,

                attachments

            )






def get_recent_emails(max_results=10, search_query=None):


    service = get_gmail_service()



    if service is None:

        return []




    # Gmail Search

    if search_query:


        result = service.users().messages().list(

            userId="me",

            q=search_query,

            maxResults=max_results

        ).execute()



    else:


        result = service.users().messages().list(

            userId="me",

            maxResults=max_results

        ).execute()





    print("Gmail Response:")

    print(result)




    messages = result.get(

        "messages",

        []

    )



    emails = []





    for message in messages:



        msg = service.users().messages().get(

            userId="me",

            id=message["id"],

            format="full"

        ).execute()





        headers = msg.get(

            "payload",

            {}

        ).get(

            "headers",

            []

        )




        sender = "Unknown"

        subject = "No Subject"




        for header in headers:



            if header["name"] == "From":

                sender = header["value"]



            elif header["name"] == "Subject":

                subject = header["value"]






        body_parts = []

        attachments = []



        payload = msg.get(

            "payload",

            {}

        )




        # Scan Gmail parts

        if payload.get("parts"):


            process_parts(

                payload["parts"],

                body_parts,

                attachments

            )



        else:


            data = payload.get(

                "body",

                {}

            ).get(

                "data"

            )


            if data:


                try:

                    body_parts.append(

                        base64.urlsafe_b64decode(

                            data

                        ).decode(

                            "utf-8",

                            errors="ignore"

                        )

                    )


                except Exception:

                    pass




        body = "\n".join(

            body_parts

        )





        # Remove duplicate attachments

        unique_attachments = []

        seen = set()



        for item in attachments:


            if item["name"] not in seen:


                unique_attachments.append(item)

                seen.add(
                    item["name"]
                )



        attachments = unique_attachments





        # Extract URLs

        links = re.findall(

            r'https?://[^\s"\'>]+',

            body

        )




        snippet = msg.get(

            "snippet",

            ""

        )




        emails.append({

            "id": msg["id"],

            "sender": sender,

            "subject": subject,

            "body": body,

            "snippet": snippet,

            "links": list(set(links)),

            "attachments": attachments

        })





    print("Emails Found:")

    print(emails)




    return emails

def get_email_by_id(email_id):

    service = get_gmail_service()

    if service is None:
        return None

    msg = service.users().messages().get(
        userId="me",
        id=email_id,
        format="full"
    ).execute()

    headers = msg.get(
        "payload",
        {}
    ).get(
        "headers",
        []
    )

    sender = "Unknown"
    subject = "No Subject"

    for header in headers:

        if header["name"] == "From":
            sender = header["value"]

        elif header["name"] == "Subject":
            subject = header["value"]

    body_parts = []
    attachments = []

    payload = msg.get("payload", {})

    if payload.get("parts"):

        process_parts(
            payload["parts"],
            body_parts,
            attachments
        )

    else:

        data = payload.get(
            "body",
            {}
        ).get(
            "data"
        )

        if data:

            try:

                body_parts.append(
                    base64.urlsafe_b64decode(
                        data
                    ).decode(
                        "utf-8",
                        errors="ignore"
                    )
                )

            except Exception:
                pass

    body = "\n".join(body_parts)

    links = re.findall(
        r'https?://[^\s"\'>]+',
        body
    )

    return {

        "id": msg["id"],

        "sender": sender,

        "subject": subject,

        "body": body,

        "links": list(set(links)),

        "attachments": attachments

    }