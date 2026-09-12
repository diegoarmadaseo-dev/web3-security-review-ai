// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @title Alcancia
/// @notice Una alcancia simple: cada persona deposita y retira unicamente su
///         propio saldo. Sin logica de negocio adicional ni dependencias externas.
contract Alcancia {
    address public immutable propietario;
    mapping(address => uint256) public saldos;

    /// @dev Solo el propietario puede pausar los depositos en caso de emergencia.
    bool public pausado;

    modifier soloPropietario() {
        require(msg.sender == propietario, "Alcancia: no es el propietario");
        _;
    }

    modifier noPausado() {
        require(!pausado, "Alcancia: depositos pausados");
        _;
    }

    constructor() {
        propietario = msg.sender;
    }

    /// @notice Deposita fondos propios en la alcancia.
    function depositar() external payable noPausado {
        saldos[msg.sender] += msg.value;
    }

    /// @notice Retira hasta el saldo propio del remitente. Sigue el patron
    ///         de actualizar el estado antes de enviar los fondos.
    function retirar(uint256 monto) external {
        require(saldos[msg.sender] >= monto, "Alcancia: saldo insuficiente");
        saldos[msg.sender] -= monto;
        (bool exito, ) = msg.sender.call{value: monto}("");
        require(exito, "Alcancia: fallo el envio");
    }

    /// @notice Pausa o reanuda los nuevos depositos.
    function establecerPausa(bool valor) external soloPropietario {
        pausado = valor;
    }
}
