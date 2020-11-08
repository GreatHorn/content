import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_gh_get_policy_command(requests_mock):
    from GreatHorn import Client, gh_get_policy_command
    mock_response = util_load_json('test_data/policy.json')

    requests_mock.get('https://api.greathorn.com/v2/policy/4018', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "policyid": "4018"
    }

    response = gh_get_policy_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Policy'
    assert response.outputs_key_field == 'id'


def test_gh_get_message_command(requests_mock):
    from GreatHorn import Client, gh_get_message_command
    mock_response = util_load_json('test_data/message.json')
    requests_mock.post('https://api.greathorn.com/v2/search/events', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "id": "14807"
    }

    response = gh_get_message_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Message'
    assert response.outputs_key_field == 'eventId'
    assert response.outputs == mock_response["results"][0]
