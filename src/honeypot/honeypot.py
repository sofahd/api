from sofahutils import SofahLogger, get_own_ip
from honeypot.utils import load_json_file_to_dict
import flask, gzip, exrex, subprocess


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
            
            if answer_dict.get("type") == "content_sensitive":
                ret_response = self.serve_content_sensitive_endpoint(answer_dict=answer_dict, ip=ip, port=port, path=path, content=content)
            else:            
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
    
    def serve_content_sensitive_endpoint(self, answer_dict:dict, ip:str, port:int, content:str, path:str)->flask.Response:
        """
        This is a quick fix, for serving content sensitive endpoints.
        """
        
        content_answer = None
        content_answer_dict = answer_dict.get("content_answers", {})
        
        for answer in content_answer_dict.keys():
            if answer in content:
                content_answer = content_answer_dict[answer]

        if content_answer is None:
            log_content = { "message": "No content answer found for the given content", "content": content, "endpoint": path} 
            self.logger.warn(event_id="api.honeypot.no_content_answer", content=log_content, ip=ip, port=port)
            return flask.Response(status=404)

        elif content_answer.get("type") == "static":
            return self.serve_static_endpoint(answer_dict=content_answer, ip=ip, port=port)
    
        elif content_answer.get("type") == "checkpoint":
            return self.serve_checkpoint_endpoint(answer_dict=content_answer, ip=ip, port=port, content=content, path=path)
        

    def serve_checkpoint_endpoint(self, answer_dict:dict, ip:str, port:int, content:str, path:str)->flask.Response:
        """
        This is a quicly hacked out method to serve the checkpoint endpoints.
        """

        ret_response = flask.Response()
        file_path = content.replace("aCSHELL/../../../../../../..", "")

        content_respose = subprocess.run(f"cat {file_path}",shell=True, capture_output=True)
        
        ret_response.status=200
        ret_response.mimetype="text/html"
        
        
        if content_respose.returncode != 0:
            self.log.warn(message=f"Error while trying to read the file: {file_path}", method="api.honeypot.serve_checkpoint_endpoint", ip=ip, port=port)
            ret_response.response="Broken pipe"
            
        else:
            ret_response.response = content_respose.stdout.decode("utf-8")

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