"""
In this file some utility functions are defined that are used in the honeypot.
"""

import os, json
from typing import Union
from honeypot.exceptions import PathIsNoFileException, WrongFileTypeException

def validate_path_and_extension(path:str, extension:str):
        """
        This function can be used to validate a filepath
        If no exceptions were thrown, the filepath is ok.
        :param path: the filepath you want to verify
        :type path: str
        :param extension: the File extension you expect the path to have either with `.` at the beginning or not.
        :type extension: str
        """
        if not extension[0] == '.':
                extension = '.' + extension

        if not os.path.isfile(path=path):
                raise PathIsNoFileException(f"The path `{path}` is not pointing to a file!")
        
        if not os.path.splitext(path)[1] == extension:
                raise WrongFileTypeException(f"The supplied filepath: {path} does not point to a `{extension}` file!")


def load_json_file_to_dict(path:str)->Union[dict, list]:
        """
        Function to return a dict from a provided json file.
        :param path: The filepath to the file that contains the dict
        :type path: str
        :return: the loaded dict, or list
        """

        validate_path_and_extension(path=path, extension='.json')

        with open(path) as file:
                return json.loads(file.read())