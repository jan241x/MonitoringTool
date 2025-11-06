
import os
import sys
import json
import time

from typing import List

from alibabacloud_apig20240327.client import Client as APIG20240327Client
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_apig20240327 import models as apig20240327_models
from alibabacloud_tea_util import models as util_models
from alibabacloud_tea_util.client import Client as UtilClient
from dotenv import load_dotenv


class Sample:
    def __init__(self):
        pass

    @staticmethod
    def create_client() -> APIG20240327Client:
        """
        Initialize the Client with the credentials
        @return: Client
        @throws Exception
        """
        # 先加载 .env 中的变量（若存在）
        load_dotenv()
        # 使用环境变量中的 AccessKey/Secret 进行鉴权
        access_key_id = os.getenv('ALIYUN_ACCESS_KEY_ID')
        access_key_secret = os.getenv('ALIYUN_ACCESS_KEY_SECRET')
        region_id = os.getenv('ALIYUN_REGION_ID', 'cn-hongkong')

        if not access_key_id or not access_key_secret:
            print('缺少 AccessKey 配置，请设置 ALIYUN_ACCESS_KEY_ID 与 ALIYUN_ACCESS_KEY_SECRET')
            sys.exit(1)

        config = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region_id
        )
        # APIG endpoint: apig.{region}.aliyuncs.com
        config.endpoint = f'apig.{region_id}.aliyuncs.com'
        return APIG20240327Client(config)

    @staticmethod
    def main(
        args: List[str],
    ) -> None:
        client = Sample.create_client()
        runtime = util_models.RuntimeOptions()
        headers = {}
        try:
            interval_minutes = int(os.getenv('MONITOR_INTERVAL_MINUTES', '5'))
        except Exception:
            interval_minutes = 5

        def compose_endpoints(it):
            addrs = it.get('addresses') or it.get('Addresses') or []
            ports = it.get('ports') or it.get('Ports') or []
            endpoints = []
            if addrs:
                if any(':' in a for a in addrs):
                    endpoints = addrs
                elif ports:
                    try:
                        endpoints = [f"{a}:{p.get('port')}" for a in addrs for p in ports if p.get('port')]
                    except Exception:
                        endpoints = addrs
                else:
                    endpoints = addrs
            return endpoints

        print(f"Scheduler started. Interval: {interval_minutes} minute(s). Press Ctrl+C to stop.")
        try:
            while True:
                list_services_request = apig20240327_models.ListServicesRequest()
                try:
                    result = client.list_services_with_options(list_services_request, headers, runtime)
                    data_dict = None
                    if hasattr(result, 'body') and result.body is not None:
                        try:
                            data_json_str = UtilClient.to_jsonstring(result.body)
                            data_dict = json.loads(data_json_str)
                        except Exception:
                            if isinstance(result.body, dict):
                                data_dict = result.body

                    items = []
                    if data_dict:
                        items = (
                            data_dict.get('data', {}).get('items')
                            or data_dict.get('Data', {}).get('Items')
                            or []
                        )
                        if not isinstance(items, list):
                            items = [items]

                    total = len(items)
                    unhealthy = []
                    healthy = 0

                    print("\n=== Services (name & endpoint) ===")
                    for idx, it in enumerate(items, 1):
                        name = it.get('name') or it.get('Name') or ''
                        status = (it.get('healthStatus') or it.get('HealthStatus') or '').lower()
                        endpoints = compose_endpoints(it)
                        ep_str = ", ".join(endpoints) if endpoints else "-"
                        print(f"[{idx}] {name}  ->  {ep_str}")
                        if status == 'unhealthy':
                            unhealthy.append(it)
                        else:
                            healthy += 1

                    print("\n=== Summary ===")
                    print(f"Total: {total}, Healthy: {healthy}, Unhealthy: {len(unhealthy)}")

                    if unhealthy:
                        print("\n=== Unhealthy Services (full details) ===")
                        for i, it in enumerate(unhealthy, 1):
                            name = it.get('name') or it.get('Name') or ''
                            sid = it.get('serviceId') or it.get('ServiceId') or ''
                            gid = it.get('gatewayId') or it.get('GatewayId') or ''
                            status = it.get('healthStatus') or it.get('HealthStatus') or ''
                            addresses = it.get('addresses') or it.get('Addresses') or []
                            unendpoints = it.get('unhealthyEndpoints') or it.get('UnhealthyEndpoints') or []
                            ports = it.get('ports') or it.get('Ports') or []
                            print(f"[{i}] name={name}, serviceId={sid}, gatewayId={gid}, healthStatus={status}")
                            if addresses:
                                print(f"    addresses: {', '.join(addresses)}")
                            if ports:
                                try:
                                    print("    ports: " + ", ".join([f"{p.get('port')}({p.get('protocol')})" for p in ports]))
                                except Exception:
                                    print(f"    ports: {ports}")
                            if unendpoints:
                                print(f"    unhealthyEndpoints: {', '.join(unendpoints)}")
                except Exception as error:
                    try:
                        print(error.message)
                        print(error.data.get("Recommend"))
                    except Exception:
                        print(error)

                time.sleep(max(1, int(interval_minutes) * 60))
        except KeyboardInterrupt:
            print("\nStopped by user.")

    @staticmethod
    async def main_async(
        args: List[str],
    ) -> None:
        client = Sample.create_client()
        list_services_request = apig20240327_models.ListServicesRequest()
        runtime = util_models.RuntimeOptions()
        headers = {}
        try:
            # Copy the code to run, please print the return value of the API by yourself.
            await client.list_services_with_options_async(list_services_request, headers, runtime)
        except Exception as error:
            # Only a printing example. Please be careful about exception handling and do not ignore exceptions directly in engineering projects.
            # print error message
            print(error.message)
            # Please click on the link below for diagnosis.
            print(error.data.get("Recommend"))
            UtilClient.assert_as_string(error.message)


if __name__ == '__main__':
    Sample.main(sys.argv[1:])
