# Zero trust Module for IoT devices in  ns-3
The modules developed within this Zero Trust IoT library for ns-3 work in close coordination to form a comprehensive, layered security architecture that simulates the real-world enforcement of Zero Trust principles in constrained, distributed environments like the Internet of Things (IoT). Each module addresses a distinct facet of Zero Trust—identity, policy enforcement, encryption, session security, and observability—but their true strength lies in how they interact to build a coherent and enforceable trust boundary around every node and communication event within the network.

## Getting Started

1. Clone the ns-3 mainline code

    ```bash
    git clone -b ns-3.45 https://gitlab.com/nsnam/ns-3-dev.git
    ```
2. Change into the contrib directory

    ```bash
    cd contrib
    ```
3. Clone the Zero Trust Simulation Module

    ```bash
    git clone https://github.com/the-ns3-programmer/zero-trust-iot.git
    ```
4. Configure ns-3 and build it. Ensure [cryptopp](https://github.com/weidai11/cryptopp) is installed:

    ```bash
    ./ns3 configure --enable-examples --enable-tests -- -DNS3_CRYPTOPP=ON
    ```

    ```bash
    ./ns3 build
    ```
5. Run the examples by copying it to the scratch folder.

## Contributors

### Core Maintainers

| Name | Affiliation | Contact |
| :--- | :--- | :--- |
| **Arun Santhosh R A** | Final year B.Tech CSE, VIT Chennai | [arunsanthosh.rashok@gmail.com](mailto:arunsanthosh.rashok@gmail.com) |
| **Dr. Subbulakshmi T** | Professor, VIT Chennai | [subbulakshmibest@gmail.com](mailto:subbulakshmibest@gmail.com) |

### Release v2.0.0 Contributors

| Name | Affiliation | Contact |
| :--- | :--- | :--- |
| **Rahul S** | IInd year B.Tech CSE, VIT Chennai | [rahulsaravanan3052@gmail.com](mailto:rahulsaravanan3052@gmail.com) |
| **Muthu Venkatesh M** | IInd year B.Tech CSE, VIT Chennai | [muthuvenkat2426@gmail.com](mailto:muthuvenkat2426@gmail.com) |
| **Rahul R** | IInd year B.Tech CSE, VIT Chennai | [rahulsubha1983@gmail.com](mailto:rahulsubha1983@gmail.com) |



## License

This software is licensed under the terms of the GNU GPLv2, as like as ns-3.
See the LICENSES folder for more details.

