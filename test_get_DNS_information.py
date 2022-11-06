from main import b_recon


def test_get_DNS_information():
    b_recon1 = b_recon()
    b_recon1.domain_url = 'https://gitlab.com/'
    b_recon1.get_domain_name()
    assert b_recon1.get_DNS_information() == True


