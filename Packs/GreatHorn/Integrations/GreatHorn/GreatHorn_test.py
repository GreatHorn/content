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


def test_gh_search_message_command(requests_mock):
    from GreatHorn import Client, gh_search_message_command
    mock_response = util_load_json('test_data/message.json')
    requests_mock.post('https://api.greathorn.com/v2/search/events', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "filters": '[{"eventId":["15708"]}]'
    }

    response = gh_search_message_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Message'
    assert response.outputs_key_field == 'eventId'


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


def test_gh_remediate_message_command(requests_mock):
    from GreatHorn import Client, gh_remediate_message_command
    mock_response = util_load_json('test_data/remediate_success.json')
    requests_mock.post('https://api.greathorn.com/v2/remediation/quarantine', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "eventId": "14807",
        "action": "quarantine"
    }

    response = gh_remediate_message_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Remediation'
    assert response.outputs_key_field == 'eventId'


def test_gh_revert_remediate_message_command(requests_mock):
    from GreatHorn import Client, gh_revert_remediate_message_command
    mock_response = util_load_json('test_data/revert_success.json')
    requests_mock.post('https://api.greathorn.com/v2/remediation/revert/quarantine', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "eventId": "14807",
        "action": "quarantinerelease"
    }

    response = gh_revert_remediate_message_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Remediation'
    assert response.outputs_key_field == 'eventId'


def test_gh_set_policy_command(requests_mock):
    from GreatHorn import Client, gh_set_policy_command
    mock_response = util_load_json('test_data/set_policy_success.json')
    requests_mock.patch('https://api.greathorn.com/v2/policy/16567', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "policyid": "16567",
        "updatemethod": "patch",
        "policyjson": '{"config": ["or", ["and", {"opt": "from", "values": ["asdf@asdf.com","asdf2@asdf2.com"], "type": "regex"}]]}'  # noqa
    }

    response = gh_set_policy_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Policy'
    assert response.outputs_key_field == 'id'


def test_get_phish_reports(requests_mock):
    from GreatHorn import Client, get_phish_reports
    mock_response = util_load_json('test_data/phish_response.json')
    requests_mock.post('https://api.greathorn.com/v2/search/events', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    response = get_phish_reports(client, 100, set())

    assert len(response) == 2


def test_get_quarantine_release(requests_mock):
    from GreatHorn import Client, get_quarantine_release
    mock_response = util_load_json('test_data/release_response.json')
    requests_mock.post('https://api.greathorn.com/v2/search/events', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    response = get_quarantine_release(client, 100, set())

    assert len(response) == 2


def test_convert_to_comma_separated():
    from GreatHorn import convert_to_comma_separated
    eventIds = set(["20314", "20315", "20320"])
    result = convert_to_comma_separated(eventIds)
    assert result == "20314,20315,20320" or result == "20314,20320,20315" or result == "20315,20314,20320" or \
           result == "20315,20320,20314" or result == "20320,20314,20315" or result == "20320,20315,20314"


def testconvert_to_set():
    from GreatHorn import convert_to_set
    eventIds_str = "20314,20315,20320"
    result = convert_to_set(eventIds_str)
    assert result == set(["20314", "20315", "20320"])


def test_get_time_difference_in_sec():
    from GreatHorn import get_time_difference_in_sec
    last_time_str = "2021-01-01 09:10:30"
    time_difference_sec = get_time_difference_in_sec(last_time_str)
    assert time_difference_sec > 3500000
