import yaml
import gnupg
import pickle
import os
import tempfile
import base64

SIGKEY = 'insights_signature'

gpg = gnupg.GPG(gnupghome = '.')


def sign_them_all():
    with open('example-playbook.yml.orig', 'r') as yaml_file:
        yml = yaml.load(yaml_file, Loader=yaml.FullLoader)
        i = True
        for snippet in yml:
            if 'name' not in snippet:
                raise Exception

            snippet_serialized = pickle.dumps(snippet)
            sig = bytes(str(gpg.sign(snippet_serialized, detach = True)), 'UTF-8')
            snippet[SIGKEY] = base64.b64encode(sig)

        with(open('example-playbook.yml', 'w')) as output:
            yaml.dump(yml, output, sort_keys=False)


def validate():
    with open('example-playbook.yml', 'r') as yaml_file:
        yml = yaml.load(yaml_file, Loader=yaml.FullLoader)
        for snippet in yml:
            if 'name' not in snippet:
                raise Exception
            if SIGKEY not in snippet:
                raise Exception('Refusing to use Playbook with an unsigned snippet')

            original_snippet = dict(snippet)
            del original_snippet[SIGKEY]
            snippet_serialized = pickle.dumps(original_snippet)

            signature = snippet[SIGKEY]
            fd, fn = tempfile.mkstemp()
            os.write(fd, base64.b64decode(signature))
            os.close(fd)

            verified = gpg.verify_data(fn, snippet_serialized)
            os.unlink(fn)

            if not verified:
                raise ValueError("Signature could not be verified!")

            print('Verified snippet')

sign_them_all()
validate()
