__all__ = ['tp_link_encryption']

# Don't look below, you will not understand this Python code :) I don't.

from js2py.pyjs import *
# setting scope
var = Scope( JS_BUILTINS )
set_global_object(var)

# Code follows:
var.registers(['enc'])
@Js
def PyJsHoisted_enc_(val, nn, ee, this, arguments, var=var):
    var = Scope({'val':val, 'nn':nn, 'ee':ee, 'this':this, 'arguments':arguments}, var)
    var.registers(['nn', 'ee', 'val', 'result'])
    var.put('result', var.get('jQuery').get('rsa').callprop('encrypt', var.get('val'), var.get('nn'), var.get('ee')))
    return var.get('result')
PyJsHoisted_enc_.func_name = 'enc'
var.put('enc', PyJsHoisted_enc_)
PyJs_Object_0_ = Js({})
var.put('jQuery', PyJs_Object_0_)
PyJs_Object_1_ = Js({})
var.put('$', PyJs_Object_1_)
PyJs_Object_2_ = Js({})
var.put('navigator', PyJs_Object_2_)
@Js
def PyJs_anonymous_4_(n, this, arguments, var=var):
    var = Scope({'n':n, 'this':this, 'arguments':arguments}, var)
    var.registers(['n'])
    @Js
    def PyJs_anonymous_5_(this, arguments, var=var):
        var = Scope({'this':this, 'arguments':arguments}, var)
        var.registers([])
        return var.get('Math').callprop('random')
    PyJs_anonymous_5_._set_name('anonymous')
    return var.get('Array').callprop('apply', var.get(u"null"), var.get('Array')(var.get('n'))).callprop('map', PyJs_anonymous_5_)
PyJs_anonymous_4_._set_name('anonymous')
PyJs_Object_3_ = Js({'crypto':PyJs_anonymous_4_})
var.put('window', PyJs_Object_3_)
pass
pass


# Add lib to the module scope
tp_link_encryption = var.to_python()