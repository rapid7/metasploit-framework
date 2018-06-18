(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.attach = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function attach(term, socket, bidirectional, buffered) {
    var addonTerminal = term;
    bidirectional = (typeof bidirectional === 'undefined') ? true : bidirectional;
    addonTerminal.__socket = socket;
    addonTerminal.__flushBuffer = function () {
        addonTerminal.write(addonTerminal.__attachSocketBuffer);
        addonTerminal.__attachSocketBuffer = null;
    };
    addonTerminal.__pushToBuffer = function (data) {
        if (addonTerminal.__attachSocketBuffer) {
            addonTerminal.__attachSocketBuffer += data;
        }
        else {
            addonTerminal.__attachSocketBuffer = data;
            setTimeout(addonTerminal.__flushBuffer, 10);
        }
    };
    var myTextDecoder;
    addonTerminal.__getMessage = function (ev) {
        var _this = this;
        var str;
        if (typeof ev.data === 'object') {
            if (!myTextDecoder) {
                myTextDecoder = new TextDecoder();
            }
            if (ev.data instanceof ArrayBuffer) {
                str = myTextDecoder.decode(ev.data);
                displayData(str);
            }
            else {
                var fileReader = new FileReader();
                fileReader.addEventListener('load', function () {
                    str = myTextDecoder.decode(_this.result);
                    displayData(str);
                });
                fileReader.readAsArrayBuffer(ev.data);
            }
        }
        else if (typeof ev.data === 'string') {
            displayData(ev.data);
        }
        else {
            throw Error("Cannot handle \"" + typeof ev.data + "\" websocket message.");
        }
    };
    function displayData(str, data) {
        if (buffered) {
            addonTerminal.__pushToBuffer(str || data);
        }
        else {
            addonTerminal.write(str || data);
        }
    }
    addonTerminal.__sendData = function (data) {
        if (socket.readyState !== 1) {
            return;
        }
        socket.send(data);
    };
    socket.addEventListener('message', addonTerminal.__getMessage);
    if (bidirectional) {
        addonTerminal.on('data', addonTerminal.__sendData);
    }
    socket.addEventListener('close', function () { return detach(addonTerminal, socket); });
    socket.addEventListener('error', function () { return detach(addonTerminal, socket); });
}
exports.attach = attach;
function detach(term, socket) {
    var addonTerminal = term;
    addonTerminal.off('data', addonTerminal.__sendData);
    socket = (typeof socket === 'undefined') ? addonTerminal.__socket : socket;
    if (socket) {
        socket.removeEventListener('message', addonTerminal.__getMessage);
    }
    delete addonTerminal.__socket;
}
exports.detach = detach;
function apply(terminalConstructor) {
    terminalConstructor.prototype.attach = function (socket, bidirectional, buffered) {
        attach(this, socket, bidirectional, buffered);
    };
    terminalConstructor.prototype.detach = function (socket) {
        detach(this, socket);
    };
}
exports.apply = apply;



},{}]},{},[1])(1)
});
//# sourceMappingURL=attach.js.map
