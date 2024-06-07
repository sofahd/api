from sofahutils import SofahLogger, get_own_ip
from honeypot.utils import load_json_file_to_dict
import flask, gzip, exrex


class Honeypot:
    """
    This Class is used to implement the logic behind the api.
    """

    def __init__(self, logger:SofahLogger, answerset_path:str) -> None:
        """
        Constructor for the Honeypot
        
        ---
        :param logger: the logger object
        :type logger: SofahLogger
        """
        self.answerset = load_json_file_to_dict(path=answerset_path)
        self.logger = logger

        for endpoint in self.answerset["endpoints"].keys():
            self._randomize_endpoint(endpoint_path=self.answerset["endpoints"][endpoint]["path"], placeholder_dict=self.answerset["placeholders"])

    def endpoint(self, path:str, args:dict, content:str, http_method:str, ip:str, port:int) -> flask.Response:
        """
        This method expects the endpoint that was tried to reach and will give a response accordingly.

        ---
        :param path: the path to the endpoint that was tried to reach
        :type path: str
        :param args: the args MultiDict from the request
        :type args: dict
        :param content: the content from the request
        :type content: str
        :param http_method: the type of the request
        :type http_method: str
        :param ip: The senders IP-Adress
        :type ip: str
        :param port: the source port
        :type port: int
        :return: a tuple with a dict containing the answer and an int for the response code
        """
        ret_response = None
        
        path = f"/{path}"
        if " " in path:
            path = path.replace(" ", "%20")
            
        if path in self.answerset["endpoints"].keys():
            
            if list(args.keys()) != []:
                log_content = {}
                log_content["args"] = dict(args.deepcopy())
                log_content["endpoint"] = path
                self.logger.log(event_id="api.honeypot.args", content=log_content, ip=ip, port=port)
            
            answer_dict = self.answerset["endpoints"][path]
            log_content = {"endpoint": path, "type": http_method, "content": content, "message": f"Endpoint: {path} was reached!"}
            self.logger.log(event_id="api.honeypot.endpoint", content=log_content, ip=ip, port=port)
            ret_response = self.serve_static_endpoint(answer_dict=answer_dict, ip=ip, port=port)
        
        elif (not ("favicon" in path or "ico" in path)) and self.answerset.get("default_endpoint") is not None: 
            log_dict = {
                "unknown_endpoint": path,
                "type": http_method,
                "content_of_request": content
            }
            self.logger.log(event_id="api.honeypot.unknown_endpoint", content=log_dict, ip=ip, port=port)
            answer_dict = self.answerset["default_endpoint"]
            ret_response = self.serve_static_endpoint(answer_dict=answer_dict, ip=ip, port=port)
        
        else:
            self.logger.warn(message=f"Either unsupported favicon or unknown endpoint without set default endpoint: {path}", method="api.honeypot.favicon_or_unknown_endpoint", ip=ip, port=port)
            ret_response = flask.Response(status=404)

        return ret_response

    def serve_static_endpoint(self, answer_dict:dict, ip:str, port:int)->flask.Response:
        """
        This method is used to serve all static endpoints.
        
        ---
        :param answer_dict: the dictionary containing information about one specific answer
        :type answer_dict: dict
        :param args: the url encoded parameters associated with the request
        :type args: dict
        :param ip: The senders IP-address
        :type ip: str
        :param port: the source port
        :type port: int
        :return: a flask.Response object containing the response.
        """

        ret_response = flask.Response()

        self.logger.log(event_id='api.honeypot.static_endpoint', content=answer_dict, ip=ip, port=port)
        try:
            ret_response.response = open(answer_dict['path'], "r").read()

            if answer_dict.get('gzip', False):
                ret_response.data = gzip.compress(data=open(answer_dict['path'],'rb').read())
        except Exception:
            ret_response = flask.send_file(answer_dict['path'], mimetype=answer_dict["headers"].get("Content-Type", "text/html"))
        return ret_response
        
    def _randomize_endpoint(self, endpoint_path:str, placeholder_dict:dict):
        """
        This method can be used to replace placeholders in the answer files of the endpoints with the randomized values.
        Here, also the ip gets set to the correct value.

        ---
        :param endpoint_path: the path to the endpoint
        :type endpoint_path: str
        :param placeholder_dict: the dictionary containing the placeholder and the values to replace them with
        :type placeholder_dict: dict
        """

        processed_dict = {}
        for placeholder, value in placeholder_dict.items():
            if placeholder == "<ip>":
                processed_dict[placeholder] = get_own_ip(api_list=["https://api.seeip.org/","https://api.ipify.org/"], logger=self.logger)
            else:
                processed_dict[placeholder] = self._create_value_from_regex(value)

        try:
            with open(endpoint_path, 'r') as file:
                content = file.read()

            for placeholder, value in processed_dict.items():
                content = content.replace(placeholder, value)

            with open(endpoint_path, 'w') as file:
                file.write(content)
        except Exception as e:
            self.logger.warn(message=f"Error while replacing placeholders in {endpoint_path}", method="api.honeypot._randomize_endpoint")


    def _create_value_from_regex(self, regex:str)->str:
        """
        This method can be used to create a value from a given regex.

        ---
        :param regex: the regex to create the value from
        :type regex: str
        :return: the created value
        """
        
        return exrex.getone(regex)