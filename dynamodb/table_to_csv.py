"""
Export DynamoDb table to csv file
"""

from boto3 import session
import csv
import logging

# Setup logging
log_format = '%(asctime)s [%(filename)s:%(lineno)s - %(funcName)s()] [%(levelname)s] %(message)s'
logging.basicConfig(format=log_format)
logger = logging.getLogger("dynamo_to_csv")
logger.setLevel(logging.INFO)

boto_session = session.Session(profile_name="Apps")


def main(table, output=None):
    """Export DynamoDb Table."""
    print('export dynamodb: {}'.format(table))
    data = read_dynamodb_data(table)
    output_filename = table + '.csv'
    if output is not None:
        output_filename = output
    write_to_csv_file(data, output_filename)


def get_keys(data):
    keys = set([])
    for item in data:
        keys = keys.union(set(item.keys()))
    return keys


def read_dynamodb_data(table):
    """
    Scan all item from dynamodb.
    :param table: String
    :return: Data in Dictionary Format.
    """
    print('Connecting to AWS DynamoDb')
    dynamodb_resource = boto_session.resource('dynamodb')
    table = dynamodb_resource.Table(table)

    print('Downloading ', end='')
    keys = []
    for item in table.attribute_definitions:
        keys.append(item['AttributeName'])
    keys_set = set(keys)
    item_count = table.item_count
    print('Total item count: '+str(item_count))
    raw_data = table.scan()
    if raw_data is None:
        return None

    items = raw_data['Items']
    field_names = set([]).union(get_keys(items))
    current_iteration = raw_data['Count']
    cur_total = (len(items) + current_iteration)
    print("Current iteration: {},  Total downloaded: {}".format(current_iteration, len(items)))

    while raw_data.get('LastEvaluatedKey'):
        raw_data = table.scan(ExclusiveStartKey=raw_data['LastEvaluatedKey'])
        items.extend(raw_data['Items'])
        field_names = field_names.union(get_keys(items))
        current_iteration = raw_data['Count']
        print("Current iteration: {},  Total downloaded: {}".format(current_iteration, len(items)))



    for field_name in field_names:
        if field_name not in keys_set:
            keys.append(field_name)
    return {'items': items, 'keys': keys}


def write_to_csv_file(data, filename):
    """
    Write to a csv file.
    :param data:
    :param filename:
    :return:
    """
    if data is None:
        return

    print("Writing to csv file.")
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, delimiter=',', fieldnames=data['keys'],
                                quotechar='"')
        writer.writeheader()
        writer.writerows(data['items'])


if __name__ == '__main__':
    main(table='neo_app_sense_event_master')






