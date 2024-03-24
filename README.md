# PrivGuardROS

By Tianhao Wang, Ke Chen, Jiahao Guo, Xiying Zhao

HNU, RobAI-Lab

## What is PrivGuardROS
PrivGuardROS is a private data storage system for high privacy protection of sensitive data in robotics applications. The system uses three main technologies: blockchain, IPFS, and HybridABEnc. PrivGuardROS provides a user-friendly framework for secure storage and reliable sharing of private data.

PrivGuardROS uses blockchain technology to ensure data immutability, decentralized management, resistance to tampering, transparency and traceability. Based on IPFS technology, the system also provides excellent storage stability and efficient data retrieval capability. In addition, by introducing the HybridABEnc solution, PrivGuardROS takes privacy to the next level by supporting attribute-based fine-grained access control, allowing the system to dynamically manage access to data based on a user's role, task, or other attributes.

This system is designed to provide a safe, reliable, efficient and highly privacy-protected solution for sensitive information storage and sharing in the robot operating system (ROS) environment. By combining these technologies, it aims to protect highly sensitive private data, including its secure storage, reliable sharing and privacy protection.

## How to use

#### Step 1 : Prepare related environment configurations
The HybridABEnc solution in PrivGuardROS relies on the Charme-Crypto library and ensures that your Python environment configuration includes both Python 3.7 and Python 3.10 versions. At the same time, the related configuration of blockchain and IPFS can be set according to the characteristics of your system. In addition, you will need to install and configure the Redis database. As for redis Settings, please refer to [the] (https://redis.io/download).

#### Step 2 : Registration
To register the identity, please run the following codes:

```
cd $PrivGuardROS
python register.py
```

And follow the instructions.

#### Step 3 : Start monitoring and data processing

Run the following code to initialize the variable:

```
cd $PrivGuardROS
python general_control_official.py
```

When you enter the folder path and topic type, the system will automatically enable the monitoring of related topics. However, before you start monitoring, make sure that the 'redis' module and your ROS topic publishing node are functioning properly.

## Contact Us
If you have any questions here, please post them as Github issues, or email Tianhao Wang at [wangtianhao@hainanu.edu.cn](mailto:wangtianhao@hainanu.edu.cn).
