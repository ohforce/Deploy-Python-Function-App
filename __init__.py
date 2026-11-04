import logging
import os
import azure.functions as func
import requests
import datetime
import hashlib
import hmac
import base64

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = hmac.new(decoded_key, string_to_hash.encode('utf-8'), hashlib.sha256).digest()
    authorization = "SharedKey {}:{}".format(customer_id, base64.b64encode(encoded_hash).decode('utf-8'))
    return authorization

def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'
    
    headers = {
        'Content-Type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    
    response = requests.post(uri, data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        logging.info("Logs successfully uploaded to Log Analytics.")
    else:
        logging.error(f"Error uploading logs: {response.status_code}")

def main(myblob: func.InputStream):
    logging.info(f"Python blob trigger function processed blob \n"
                 f"Name: {myblob.name}\n"
                 f"Size: {myblob.length} bytes")
    
    # 파일 내용 읽기
    file_content = myblob.read().decode('utf-8')
    
    # 예시: 로그 파싱 로직 (필요에 따라 JSON 변환 또는 정규식 파싱 적용)
    parsed_data = {
        "FileName": myblob.name,
        "RawContent": file_content,
        "ProcessedTime": datetime.datetime.utcnow().isoformat()
    }
    
    import json
    body = json.dumps([parsed_data])
    
    # 환경 변수에서 Log Analytics Workspace ID 및 Key 가져오기
    customer_id = os.environ.get('LOG_WORKSPACE_ID')
    shared_key = os.environ.get('LOG_WORKSPACE_KEY')
    
    if customer_id and shared_key:
        post_data(customer_id, shared_key, body, log_type="DevSecOpsParser")
    else:
        logging.warning("Log Analytics credentials are not set.")