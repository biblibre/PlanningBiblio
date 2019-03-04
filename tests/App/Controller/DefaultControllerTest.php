<?php

namespace Tests\App\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;

require_once __DIR__ . '/../../../vendor/autoload.php';

class DefaultControllerTest extends WebTestCase
{
    static protected function getKernelClass() {
        return 'App\Kernel';
    }

    public function testOne() {
        $client = static::createClient();

        $session = $client->getContainer()->get('session');
        $session->set('login_id', 1);
        $cookie = new Cookie($session->getName(), $session->getId());
        $client->getCookieJar()->set($cookie);

        $crawler = $client->request('GET', '/index.php?page=planning/modeles/index.php');
        $this->assertEquals('Aucun modèle enregistré', trim($crawler->filter('#content')->text()));
    }
}
