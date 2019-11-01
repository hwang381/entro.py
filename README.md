# entro.py
Easily create network chaos among your Vagrant VMs

## Installation
### Clone the code
```bash
mkdir -p ~/.entro.py
git clone https://github.com/hwang381/entro.py.git ~/.entro.py
```

### Add the repo to your `$PATH`
For example, in your `.bashrc` or `.zshrc`, add this line
```bash
export PATH=$PATH:$HOME/.entro.py
```

## Usage
Try to run `entro.py` under a Vagrant root dir

## Caveats
This tool currently assumes
* You are using a set of Vagrant VMs that
    * are interconnected
    * are VirtualBox VMs
    * use Linux
    * have `iptables` installed
    * have hostnames that are route-able from the your Vagrant host machine, e.g. using Vagrant plugin such as [`vagrant-hostmanager`](https://github.com/devopsgroup-io/vagrant-hostmanager)
