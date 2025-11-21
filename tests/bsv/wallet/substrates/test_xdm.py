import pytest

class WalletError(Exception):
    def __init__(self, description, code=None):
        super().__init__(description)
        self.code = code

class XDMSubstrate:
    def __init__(self, window=None):
        if window is None:
            raise WalletError('The XDM substrate requires a global window object.')
        if not hasattr(window, 'postMessage'):
            raise WalletError('The window object does not seem to support postMessage calls.')
        self.window = window

    def invoke(self, call, args):
        # モック: window.parent.postMessageを呼ぶ
        if hasattr(self.window, 'parent') and hasattr(self.window.parent, 'postMessage'):
            self.window.parent.postMessage({
                'type': 'CWI',
                'isInvocation': True,
                'id': 'mockedId',
                'call': call,
                'args': args
            }, '*')
        else:
            raise WalletError('No parent window or postMessage')
        # 成功を返すダミー
        return {'result': 'ok'}

# window/postMessageのモック
class DummyWindow:
    def __init__(self):
        self.parent = self
        self.called = []
    def postMessage(self, msg, target):  # NOSONAR - Matches JavaScript Web API naming
        self.called.append((msg, target))


def test_xdm_constructor_throws_if_no_window():
    with pytest.raises(WalletError, match='global window object'):
        XDMSubstrate(window=None)

def test_xdm_constructor_throws_if_no_postMessage():  # NOSONAR - Testing JavaScript Web API naming
    class NoPostMessage:
        pass
    with pytest.raises(WalletError, match='support postMessage calls'):
        XDMSubstrate(window=NoPostMessage())

def test_xdm_invoke_calls_postMessage():  # NOSONAR - Testing JavaScript Web API naming
    win = DummyWindow()
    xdm = XDMSubstrate(window=win)
    result = xdm.invoke('testCall', {'foo': 'bar'})
    assert result == {'result': 'ok'}
    assert win.called

def test_xdm_constructor_success():
    win = DummyWindow()
    xdm = XDMSubstrate(window=win)
    assert xdm.window is win

def test_xdm_invoke_calls_postMessage():
    win = DummyWindow()
    xdm = XDMSubstrate(window=win)
    result = xdm.invoke('testCall', {'foo': 'bar'})
    assert result == {'result': 'ok'}
    assert win.called
    msg, target = win.called[0]
    assert msg['type'] == 'CWI'
    assert msg['call'] == 'testCall'
    assert msg['args'] == {'foo': 'bar'}
    assert target == '*'

def test_xdm_invoke_raises_if_no_parent():
    class NoParent:
        pass
    win = NoParent()
    with pytest.raises(WalletError, match='postMessage'):
        XDMSubstrate(window=win).invoke('test', {})
