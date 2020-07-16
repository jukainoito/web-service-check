import requests
import argparse
import boto3
import datetime
from boto3.dynamodb.conditions import Key


class DynamoDB(object):

    def __init__(self, table_name='WebServiceCheck', dynamo_db=None):
        if dynamo_db is None:
            self.dynamo_db = boto3.resource('dynamodb', region_name='ap-southeast-1')
        else:
            self.dynamo_db = dynamo_db
        self.table_name = table_name
        self.create_table()
        self.table = self.dynamo_db.Table(self.table_name)

    def create_table(self):
        try:
            table = self.dynamo_db.create_table(
                TableName=self.table_name,
                KeySchema=[
                    {
                        'AttributeName': 'url',
                        'KeyType': 'HASH'  # Partition key
                    }
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': 'url',
                        'AttributeType': 'S'
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 10,
                    'WriteCapacityUnits': 10
                }
            )
            return table
        except Exception as e:
            pass

    def scan(self):
        response = self.table.scan()
        return response.get('Items', [])

    def put(self, url, success):
        if url is None:
            return
        response = self.table.put_item(
            Item={
                'url': url,
                'date': int(datetime.datetime.now().timestamp()),
                'success': success
            }
        )
        return response


def init_argument_parser(parser):
    parser.add_argument('-hook', '--hook', help='hook url', metavar="hook url")


def check(url):
    try:
        r = requests.get(url)
    except requests.exceptions.ConnectionError:
        return False
    return True


def call_hook(hook_url, url, success):
    msg = '{}\tis\t{}'.format(url, 'up' if success else 'down')
    payload = {'msg': msg}
    requests.post(hook_url, json=payload)


def main():
    parser = argparse.ArgumentParser()
    init_argument_parser(parser)
    args = parser.parse_args()
    hook_url = args.hook
    dynamodb = DynamoDB()
    items = dynamodb.scan()
    for item in items:
        success = check(item['url'])
        dynamodb.put(item['url'], success)
        if item['success'] != success and hook_url is not None:
            try:
                call_hook(hook_url, item['url'], success)
            except:
                pass


if __name__ == '__main__':
    main()
