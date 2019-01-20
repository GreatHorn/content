import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import pyshark
from datetime import datetime


def file_has_extension(file_name, extensions):
    """
    Check if a file name has an extension.
    Returns true/false

    :param file_name: the file name to check against.
    :param extensions: extensions to test if exists in file_name.
    :return: True if one of the extensions is in the file_name
    """
    for ext in extensions:
        if file_name.endswith(ext):
            return True

    return False


def find_entry_id_by_name(file_name, extensions=None):
    """
    Scan all entries and find corresponding entry id by file name
    extensions, an array used to furthur filter the entries.

    :param file_name: find by file name.
    :param extensions:  filter more by the file extension.
    :param exit: should exit if there is an error.
    :return: the found entryID
    """
    entries = demisto.executeCommand('getEntries', {})
    found_entry_id = None
    for entry in entries:
        entry_file_name = demisto.get(entry, 'File')
        is_correct_file = file_name.lower() == entry_file_name.lower()
        has_correct_extension = file_has_extension(file_name, extensions) if extensions else True

        if is_correct_file and has_correct_extension:
            found_entry_id = entry['ID']
            break

    if not found_entry_id:
        demisto.results({"Type": entryTypes["note"],
                        "ContentsFormat": formats["markdown"],
                        "Contents": "### No file found",
                        "EntryContext": {"PcapHTTPExtractor.Flows": []}
        })
        sys.exit(0)

    return found_entry_id


def get_entry_from_args():
    """
        Handle finding the file entry using the user supplied arguments
         return the entry or quits script entirely.

        :rtype: object containing the entry of the found file and the entry_id or error & exit
    """
    # Get the pcap file from arguments
    entry_id = None
    if 'pcapFileName' in demisto.args() \
            and not 'entryID' in demisto.args():

        PCAP_FILE = demisto.args()["pcapFileName"]
        entry_id = find_entry_id_by_name(PCAP_FILE, [".pcap", ".cap", ".pcapng"])
    elif 'entryID' in demisto.args():
        entry_id = demisto.args()["entryID"]
    else:
        return_error('You must set pcapFileName or entryID when executing PcapHTTPExtract script')

    res = demisto.executeCommand('getFilePath', {'id': entry_id})

    if len(res) > 1 and res[0]['Type'] == entryTypes['error']:
        return_error('Failed to get the file path for entry: ' + entry_id)

    return res, entry_id


def parse_capture(capture_object):
    """
        Parse a capture object into a readable http dict

        :param capture_object: the pyshark capture object from file
        :return: a pythonic dict of result
    """
    try:
        http_object_tshark = capture_object.http.__dict__["_all_fields"]
    except KeyError:
        return '{"error": "No readable result"}'

    # Remove unecessary attributes of the object
    blacklist_keys = ["_ws", "http.content_length_header",
                      "http.request", "http.response.phrase", "http.chat",
                      "http.cookie_pair", ]
    for bk in blacklist_keys:
        http_object_tshark = {k: v for k, v in http_object_tshark.items() if not k.startswith(bk)}

    if "" in http_object_tshark:
        del http_object_tshark[""]  # Some empty key that is a duplicate

    return http_object_tshark


def parse_pcap_http(pcap_file_path):
    """
        Prints the headers and body of the http response.
        By deafult returns a dict of the results.
        Will return and exit if no http flows found

        :param pcap_file_path: local path of file (after getting the entryID)
        :return: return all http packets in a list
    """

    packets = pyshark.FileCapture(pcap_file_path)
    http_packets = []

    for packet in packets:

        # Check if this is an HTTP Packet
        if 'http' in packet:
            packet = parse_capture(packet)
            http_packets.append(packet)

    if len(http_packets) == 0:
        return_error('No HTTP flows found in specified file.')

    return http_packets


def markdown_packets(http_flows):
    """
        Convert a json list of packets into a markdown table

        :param http_flows: a list of http packets
        :return: a string of markdown
    """
    result_nobody_template = "---\n{res}\n---"
    result_template = "---\n{res}\n```html\n{body}\n```\n---"
    markdown_result = ""

    for i, packet in enumerate(http_flows):
        has_body = "HttpFileData" in packet
        if not has_body:
            row = result_nobody_template.format(
                res=tableToMarkdown("HTTP #{}".format(i + 1),
                                    packet,
                                    packet.keys()
                                    )
            )
        else:
            row = result_template.format(
                res=tableToMarkdown("HTTP #{}".format(i),
                                    packet,
                                    packet.keys()
                                    ),
                body=packet["HttpFileData"]
            )

        markdown_result += row
    return markdown_result


def _fix_key(keys_list):
    """
    Fix the key to abide the context
    :param keys_list:
    :return:
    """
    key_name = ""
    for k in keys_list:
        if "_" in k:
            key_name += _fix_key(k.split("_"))
        else:
            key_name += k.capitalize()

    return key_name


def fix_http_keys(http_flows):
    """
    Fixes the http_flows's keys to abide the Demisto conventions.
    :param http_flows: a list of http packets
    :return: the object containing all of the filtered and formatted flows.
    """

    relevant_context = ["http.host", "http.user_agent", "http.response.code",
                        "http.response.version", "http.date", "http.last_modified",
                        "http.request.uri", "http.request.full_uri",
                        "http.request.method", "http.file_data", "http.accept",
                        "http.content_type"]

    allowed_contect_types = ("text", "application/json", "multipart/form-data",
                             "application/xml", "application/xhtml+xml",
                             "application/ld+json", "application/javascript",
                             "multipart/alternative","application/x-www-form-urlencoded",
                             )

    context_list = []
    flow_index = 0
    for flow in http_flows:
        flow_index += 1
        cd = {"ResultIndex": flow_index}

        cd.update({_fix_key(k.split(".")): v for k, v in flow.items() if k in relevant_context})

        # Convert to ISO time
        if "HttpDate" in cd:
            cd['HttpDate'] = datetime.strptime(cd['HttpDate'], '%a, %d %b %Y %H:%M:%S %Z').isoformat()

        # Allow only whitelist of content
        if "HttpContentType" in cd:
            if not cd["HttpContentType"].startswith(allowed_contect_types):
                cd["HttpContentType"] = "Unsupported Content Type"

        context_list.append(cd)

    return context_list


if __name__ == "builtins":
    try:
        # Parse the arguments
        pcap_file_path_in_container, pcap_entry_id = get_entry_from_args()
        pcap_file_path_in_container = pcap_file_path_in_container[0]['Contents']['path']
        LIMIT = demisto.args()["limit"]
        START = demisto.args()["start"]

        # Work on the pcap file and return a result
        http_flows = parse_pcap_http(pcap_file_path_in_container)

        if START:
            http_flows = http_flows[int(START):]
        if LIMIT:
            http_flows = http_flows[:int(LIMIT)]

        http_flows = fix_http_keys(http_flows)
        markdown_results = markdown_packets(http_flows)

        demisto.results({"Type": entryTypes["note"],
                         "ContentsFormat": formats["markdown"],
                         "Contents": markdown_results,
                         "EntryContext": {"PcapHTTPExtractor.Flows": http_flows}
                         })

    except Exception as ex:
        import traceback

        return_error("Error occurred while parsing output from command. Exception info:\n" \
                     + str(ex) + "\n\nTrace:\n" + str(traceback.format_exc()))
