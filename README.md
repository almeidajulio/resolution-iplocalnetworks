# GAT Resolution Iplocalnetworks
<a href src="https://gat.digital" target="_blank"><img align="right" height="70" src="https://www.gat.digital/wp-content/uploads/2021/05/logo-gat-padrao-negativo.png"></a>
<p align="left">
  <img alt="Github top language" src="https://img.shields.io/github/languages/top/almeidajulio/resolution-iplocalnetworks?color=56BEB8">

  <img alt="Github language count" src="https://img.shields.io/github/languages/count/almeidajulio/resolution-iplocalnetworks?color=56BEB8">

  <img alt="Repository size" src="https://img.shields.io/github/repo-size/almeidajulio/resolution-iplocalnetworks?color=56BEB8">
</p>
<br>
<br>
<div align="center" id="top"> 
  <img src="./.github/app.gif" alt="Resolution Iplocalnetworks" />

  &#xa0;
</div>

#### Directory Structure 
<br>

    .
    ├── ...
    ├── data                    # .nessus original files
    ├── data_changed            # .nessus file after changes
    ├── src                     # source program
    │   ├── hostnames           # Folder with control file
    │   ├── logging             # Log Folder
    │   │   └── logging.log     # File logging application
    │   └── config.json         # Configuration file (network escope)
    └── ...

<br>

### :dart: About ##

Keeping a fixed private IP,  controlling IPs generated in DHCP and internal network VPN in nessus scanner files

<!-- ## :sparkles: Features ##

:heavy_check_mark: Feature 1;\
:heavy_check_mark: Feature 2;\
:heavy_check_mark: Feature 3; -->

### :rocket: Technologies ##

The following tools were used in this project:

- [Python](https://www.python.org/)


### :white_check_mark: Requirements ##

Before starting :checkered_flag:, you need to have [Python](https://www.python.org/) and [Libs](https://pypi.org/) installed.



### :checkered_flag: Starting ##

```bash
# Clone this project
$ git clone https://github.com/almeidajulio/resolution-iplocalnetworks

# Access
$ cd resolution-iplocalnetworks

# Install requirements
$ pip install -r requirements.txt
```

### :running: Running ###

```bash
# Run the project
$ python .\src\main.py parser-nessus

# Run the project debug mode - insert flag "-d"
$ python .\src\main.py -d parser-nessus

# Run the project diferente source .nessus folder
$ python .\src\main.py parser-nessus -src 'new/source/'

# Run the project diferente destination changed file
$ python .\src\main.py parser-nessus -dst 'new/dest/nessus/'

# Run the project all parameters inline
$ python .\src\main.py -d parser-nessus -src 'new/source/' -dst 'new/dest/nessus/'
```


Made :heart: by <a href="https://github.com/almeidajulio" target="_blank">Julio Cesar Almeida </a> [wmspydev](https://github.com/wmspydev)

&#xa0;

<a href="#top">Back to top</a>
