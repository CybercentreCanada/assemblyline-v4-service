# Testing an Assemblyline service
To test an Assemblyline service in standalone mode, the
[run_service_once.py](https://bitbucket.org/cse-assemblyline/alv4_service/src/master/dev/run_service_once.py) script
can be used to run a single task through the service for testing.

## Setting up dev environment
**NOTE:** The following environment setup has only been tested on Ubuntu 18.04.

* Install required packages
```bash
sudo apt-get install build-essential libffi-dev python3.7 python3.7-dev python3-pip automake autoconf libtool
```

* Install Assemblyline v4 service package
```bash
pip3 install --user assemblyline-v4-service
```

## Using the `run_service_once.py` script
```text
usage: run_service_once.py [-h] [-d] [-o OUTPUT_DIR] service_path input_dir

positional arguments:
  service_path          python path of the service
  input_dir             path to directory where 'task.json' and the file to be
                        scanned is located

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           turn on debugging mode
  -o OUTPUT_DIR, --output_dir OUTPUT_DIR
                        path to directory where 'result.json' and
                        extracted/supplementary files should be outputted
```

### Example of running the ResultSample service
```python3.7 run_service_once.py result_sample.ResultSample /tmp```
