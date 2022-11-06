from main import b_recon


def test_get_domain_url():
    b_recon1 = b_recon()
    b_recon1.domain_url = 'https://gitlab.com/'
    b_recon1.get_domain_name()
    assert b_recon1.domain_name == 'gitlab.com'


