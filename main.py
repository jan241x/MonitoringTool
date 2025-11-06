import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime
from urllib.parse import quote

import requests


class HMACConfig:
    """HMAC配置類 / HMAC configuration class"""

    def __init__(self, url, key, secret, path="/transform", method="POST"):
        self.url = url
        self.key = key
        self.secret = secret
        self.path = path
        self.method = method
        self.accept = "application/json; charset=utf-8"
        self.content_type = "application/json; charset=utf-8"
        self.nonce = str(uuid.uuid4())
        self.timestamp = str(int(time.time() * 1000))
        self.date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

    def get_custom_headers(self):
        return {
            "x-ca-key": self.key,
            "x-ca-nonce": self.nonce,
            "x-ca-signature-method": "HmacSHA256",
            "x-ca-timestamp": self.timestamp
        }


def generate_signature(method, accept, content_type, date, path, query_params, form_params, custom_headers, secret):
    # Step 1: Build the string to sign
    string_to_sign = []

    # HTTP method
    string_to_sign.append(method.upper())

    # Accept
    string_to_sign.append(accept if accept else "")

    # Content-MD5 (for non-form bodies; this is form data so keep empty)
    string_to_sign.append("")

    # Content-Type
    string_to_sign.append(content_type if content_type else "")

    # Date
    string_to_sign.append(date if date else "")

    # Custom headers (alphabetically sorted) - only include signature-related headers
    signature_headers = {}
    for key, value in custom_headers.items():
        if key.startswith('x-ca-') and key not in ['x-ca-signature', 'x-ca-signature-headers']:
            signature_headers[key] = value

    sorted_headers = sorted(signature_headers.items(), key=lambda x: x[0])
    for key, value in sorted_headers:
        string_to_sign.append(f"{key}:{value}")

    # Path and parameters (merge query and form params, then sort)
    # For JSON content-type, only include query params in signature, not form params
    if content_type and "application/json" in content_type:
        # JSON content-type: only include query params in signature
        all_params = query_params
    else:
        # Form content-type: include both query and form params
        all_params = {**query_params, **form_params}
    
    sorted_params = sorted(all_params.items(), key=lambda x: x[0])
    if sorted_params:
        # URL encode parameter values
        encoded_params = []
        for k, v in sorted_params:
            encoded_key = quote(str(k), safe='')
            encoded_value = quote(str(v), safe='')
            encoded_params.append(f"{encoded_key}={encoded_value}")
        param_string = f"{path}?" + "&".join(encoded_params)
    else:
        param_string = path
    string_to_sign.append(param_string)

    # Join the string to sign
    string_to_sign = "\n".join(string_to_sign)

    # Step 2: Generate HMAC-SHA256 signature
    secret_bytes = secret.encode('utf-8')
    string_to_sign_bytes = string_to_sign.encode('utf-8')
    hmac_obj = hmac.new(secret_bytes, string_to_sign_bytes, hashlib.sha256)
    signature = base64.b64encode(hmac_obj.digest()).decode('utf-8')

    return signature, string_to_sign


def _load_env_file(env_path: str = ".env") -> None:
    """簡易載入 .env 檔至環境變數（不依賴第三方）/ Lightweight .env loader (no third-party)."""
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        # 載入失敗時忽略，使用預設配置 / Ignore failures and fall back to defaults
        pass


def _parse_kv_pairs(pairs: str) -> dict:
    """將 key1=val1&key2=val2 形式的字串解析為字典 / Parse key1=val1&key2=val2 into dict."""
    params = {}
    if not pairs:
        return params
    for segment in pairs.split("&"):
        if not segment:
            continue
        if "=" in segment:
            k, v = segment.split("=", 1)
            params[k] = v
        else:
            # 僅有鍵無值時設為空字串 / Empty string when value is missing
            params[segment] = ""
    return params


def main(test_mode=False):
    # 1) 載入 .env / Load .env
    _load_env_file()

    # 2) 從環境變數讀取配置並設置預設值 / Read config from env with defaults
    base_url = os.environ.get("HMAC_BASE_URL", "https://apidev-extgw.clp.com.hk")
    path = os.environ.get("HMAC_PATH", "/transform")
    full_url = os.environ.get("HMAC_URI") or (base_url.rstrip("/") + path)

    method = os.environ.get("HMAC_METHOD", "POST").upper()
    app_key = os.environ.get("HMAC_APP_KEY", "BJKncbjVeHwalhCAGomId4rsZ3xt5axA")
    app_secret = os.environ.get("HMAC_APP_SECRET", "MwEcgUJBay1Lx8ek")

    accept_override = os.environ.get("HMAC_ACCEPT")
    content_type_override = os.environ.get("HMAC_CONTENT_TYPE")

    query_pairs = os.environ.get("HMAC_QUERY", "")
    body_pairs = os.environ.get("HMAC_BODY", "username=xiaoming&password=123456789")
    query_params = _parse_kv_pairs(query_pairs)
    
    # 检查 body_pairs 是否是 JSON 格式
    if body_pairs.strip().startswith('{') and body_pairs.strip().endswith('}'):
        try:
            # 如果是 JSON 格式，解析为字典
            form_params = json.loads(body_pairs)
        except json.JSONDecodeError:
            # JSON 解析失败，回退到表单解析
            form_params = _parse_kv_pairs(body_pairs)
    else:
        # 不是 JSON 格式，使用表单解析
        form_params = _parse_kv_pairs(body_pairs)

    # 配置 HMAC 參數 / Configure HMAC parameters
    config = HMACConfig(
        url=full_url,
        key=app_key,
        secret=app_secret,
        path=path,
        method=method
    )

    # 可選覆蓋 Accept/Content-Type / Optional override
    if accept_override:
        config.accept = accept_override
    if content_type_override:
        config.content_type = content_type_override

    custom_headers = config.get_custom_headers()

    # Generate signature
    signature, string_to_sign = generate_signature(
        config.method, config.accept, config.content_type, config.date,
        config.path, query_params, form_params, custom_headers, config.secret
    )

    # Build request headers
    # Calculate the list of headers included in signature
    signature_headers = [key for key in custom_headers.keys()
                         if key.startswith('x-ca-') and key not in ['x-ca-signature', 'x-ca-signature-headers']]

    # Construct request headers
    headers = {"Accept": config.accept, "Content-Type": config.content_type, "Date": config.date,
               "x-ca-key": config.key, "x-ca-nonce": config.nonce, "x-ca-signature-method": "HmacSHA256",
               "x-ca-timestamp": config.timestamp, "x-ca-signature": signature,
               "x-ca-signature-headers": ",".join(sorted(signature_headers)),
               "Authorization": f"HMAC-SHA256 {config.key}:{signature}"}

    # Try adding an Authorization header format
    # Format 1: HMAC-SHA256 key:signature

    # 產出等效 curl 指令 / Build equivalent curl command
    query_string = "&".join(f"{k}={v}" for k, v in query_params.items())
    url_with_query = f"{config.url}?{query_string}" if query_string else config.url
    
    # 将表单数据转换为 JSON 格式
    json_data = json.dumps(form_params) if form_params else "{}"

    curl_parts = [
        "curl",
        f"-X {config.method}",
        f"\"{url_with_query}\"",
    ]

    for hk, hv in headers.items():
        curl_parts.append(f"-H \"{hk}: {hv}\"") 

    if json_data != "{}":
        curl_parts.append(f"--data \"{json_data}\"")

    curl_cmd = " ".join(curl_parts)
    # PowerShell often aliases `curl` to Invoke-WebRequest. Use curl.exe to force the real curl binary.
    curl_cmd_powershell = curl_cmd.replace("curl ", "curl.exe ", 1)

    # 輸出結果 / Output results
    print("=== HMAC 簽名測試 / HMAC Signature Test ===")
    print(f"URL: {config.url}")
    print(f"方法/Method: {config.method}")
    print(f"路徑/Path: {config.path}")
    print(f"查詢參數/Query Params: {query_params}")
    print(f"表單參數/Form Params: {form_params}")
    print(f"\n簽名字串/StringToSign:")
    print(repr(string_to_sign))
    print(f"\n簽名/Signature: {signature}")
    print(f"\n請求標頭/Request Headers:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    print(f"\n等效 curl（bash/zsh）/ Equivalent curl (bash/zsh):")
    print(curl_cmd)
    print(f"\n等效 curl（Windows PowerShell）/ Equivalent curl (Windows PowerShell):")
    print(curl_cmd_powershell)

    if not test_mode:
        # 發送請求 / Send request
        try:
            # 将表单数据转换为 JSON 格式发送
            json_data = json.dumps(form_params) if form_params else "{}"
            response = requests.post(config.url, headers=headers, params=query_params, data=json_data)
            print(f"\n回應代碼/Response code: {response.status_code}")
            print(f"回應內文/Response body: {response.text}")
            print(f"\n回應標頭/Response headers:")
            for key, value in response.headers.items():
                print(f"  {key}: {value}")

            if response.status_code != 200:
                error_msg = response.headers.get("X-Ca-Error-Message", "No error message / 無錯誤訊息")
                print(f"\n錯誤訊息/Error message: {error_msg}")
                if "StringToSign" in error_msg:
                    print("伺服器簽名字串/Server StringToSign:", error_msg)

        except requests.exceptions.ConnectionError as e:
            print(f"\n連線錯誤/Connection error: {e}")
        except Exception as e:
            print(f"\n請求錯誤/Request error: {e}")


if __name__ == "__main__":
    main()