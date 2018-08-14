/* This addon will provide front end interface to meterpreter console. It is designed to handle IO operation on the terminal. */

(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.fit = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
        "use strict";
        Object.defineProperty(exports, "__esModule", { value: true });
        
        function WebConsoleAttach(term, socket, bidirectional, buffered) {
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
            addonTerminal.__getMessage = function (ev) {
                var data = JSON.parse(ev.data);
                if (data[0] === 'stdout') {
                    if (buffered) {
                        addonTerminal.__pushToBuffer(data[1]);
                    }
                    else {
                        addonTerminal.write(data[1]);
                    }
                }
            };
            addonTerminal.__sendData = function (data) {
                socket.send(JSON.stringify(['stdin', data]));
            };
            addonTerminal.__setSize = function (size) {
                socket.send(JSON.stringify(['set_size', size.rows, size.cols]));
            };
            socket.addEventListener('message', addonTerminal.__getMessage);
            if (bidirectional) {
                addonTerminal.on('data', addonTerminal.__sendData);
            }
            addonTerminal.on('resize', addonTerminal.__setSize);
            socket.addEventListener('close', function () { return WebConsoleDetach(addonTerminal, socket); });
            socket.addEventListener('error', function () { return WebConsoleDetach(addonTerminal, socket); });
        }
        exports.WebConsoleAttach = WebConsoleAttach;
        function WebConsoleDetach(term, socket) {
            var addonTerminal = term;
            addonTerminal.off('data', addonTerminal.__sendData);
            socket = (typeof socket === 'undefined') ? addonTerminal.__socket : socket;
            if (socket) {
                socket.removeEventListener('message', addonTerminal.__getMessage);
            }
            delete addonTerminal.__socket;
        }
        exports.WebConsoleDetach = WebConsoleDetach;
        function apply(terminalConstructor) {
            terminalConstructor.prototype.WebConsoleAttach = function (socket, bidirectional, buffered) {
                return WebConsoleAttach(this, socket, bidirectional, buffered);
            };
            terminalConstructor.prototype.WebConsoleDetach = function (socket) {
                return WebConsoleDetach(this, socket);
            };
        }
        exports.apply = apply;

    },{}]},{},[1])(1)
});
//# sourceMappingURL=fit.js.map