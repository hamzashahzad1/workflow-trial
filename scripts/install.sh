#!/bin/bash
set -x

sudo apt-get install cppcheck ccache curl flex bison rpm doxygen ninja-build graphviz auditd ifupdown libaudit-dev pkg-config unzip uthash-dev curl audispd-plugins -y

echo "Installing Auditd"
# sudo cp auditd.conf /etc/audit/
sudo cp 10-zeek_agent.rules /etc/audit/rules.d/

sudo systemctl enable --now auditd

sudo sed -i 's/no/yes/g' /etc/audisp/plugins.d/af_unix.conf

sudo systemctl restart auditd

echo "Building Zeek"
cd ../
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DZEEK_AGENT_ENABLE_INSTALL:BOOL=ON -DZEEK_AGENT_ENABLE_TESTS:BOOL=ON -DZEEK_AGENT_ZEEK_COMPATIBILITY:STRING="3.1" ${HOME}/zeek-agent/
cmake --build . -v

sudo mkdir /etc/zeek-agent/
cp config.json /etc/zeek-agent/
