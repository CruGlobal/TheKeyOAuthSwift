Pod::Spec.new do |s|
  s.name             = 'TheKeyOAuthSwift'
  s.version          = '0.1.0'
  s.summary          = 'A short description of TheKeyOAuthSwift.'


  s.description      = <<-DESC
TODO: Add long description of the pod here.
                       DESC

  s.homepage         = 'https://github.com/ryan.t.carlson@cru.org/TheKeyOAuthSwift'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'ryan.t.carlson@cru.org' => 'ryan.t.carlson@cru.org' }
  s.source           = { :git => 'https://github.com/CruGlobal/TheKeyOAuthSwift.git', :tag => s.version.to_s }

  s.ios.deployment_target = '8.0'

  s.source_files = 'TheKeyOAuthSwift/Classes/**/*'  

  s.public_header_files = 'Pod/Classes/**/*.h'
  s.dependency 'GTMAppAuth'
end
