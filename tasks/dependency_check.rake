require 'rexml/document'

# Plugin to run the OWASP Dependency Checker (https://www.owasp.org/index.php/OWASP_Dependency_Check)
# to check dependencies for reported security vulnerabilities.
#
# Vulnerabilities are given a score using the Common Vulnerability Scoring System (CVSS).
# The score can range from 1 to 10 with anything over 7 being considered a critical
# vulnerability.  Users can set this in their project by setting cve.max_allowed_cvss
# to a float.
module DependencyCheck
  include Candlepin::Util

  class << self
    def task_artifacts
      Buildr.transitive('org.owasp:dependency-check-ant:jar:1.2.11')
    end

    def check(project, config)
      info("Scanning #{project} for known vulnerable dependencies...")
      cp = Buildr.artifacts(task_artifacts).each { |a| a.invoke() if a.respond_to?(:invoke) }.map(&:to_s).join(File::PATH_SEPARATOR)
      Buildr.ant('check') do |ant|
        ant.taskdef(
          :name => 'dependency_check',
          :classpath => cp,
          :classname => 'org.owasp.dependencycheck.taskdefs.DependencyCheckTask')

        ant.dependency_check(
          :applicationname => project.name,
          :reportoutputdirectory => config.report_output,
          :reportformat => "ALL") do
          dependencies = project.compile.dependencies.select do |dep|
            dep.respond_to?(:to_spec)
          end
          local_repo = project.repositories.local
          dependencies.map! do |dep|
            file_location = Buildr.repositories.locate(dep)
            Pathname.new(file_location).relative_path_from(Pathname.new(local_repo)).to_s
          end
          ant.filelist(:id => "dependency_jars", :dir => local_repo) do
            dependencies.each do |dep|
              ant.file(:name => dep)
            end
          end
        end
      end

    end

    # You can set dependency-check to fail once a certain CVSS threshold is reached, but
    # it fails by throwing an exception which Buildr does not like.  Instead, we look
    # at the XML of the report.
    def build_failed?(report_file, config, project)
      failed = false

      doc = REXML::Document.new(File.open(report_file))
      vulnerabilities = REXML::XPath.match(doc, "//vulnerability")
      info("Maximum allowable CVSS is #{config.max_allowed_cvss}") unless vulnerabilities.empty?

      scores = Hash.new { |h, k| h[k] = [] }
      vulnerabilities.each do |element|
        score = element.elements['cvssScore'].text.to_f
        file_location = element.parent.parent.elements['filePath'].text
        # Collect all the vulnerabilities for this dependency
        scores[file_location] << score
      end

      scores.each do |k, v|
        name = Pathname.new(k).relative_path_from(Pathname.new(project.repositories.local)).to_s
        word = (v.length > 1) ? "vulnerabilities" : "vulnerability"
        if v.max > config.max_allowed_cvss
          failed = true
          error("#{v.length} unacceptable #{word} in #{name} (Highest CVSS: #{v.max})")
        else
          warn("#{v.length} #{word} in #{name} (Highest CVSS: #{v.max})")
        end
      end

      info("See file://#{report_file.sub(/xml\z/, 'html')}") unless vulnerabilities.empty?
      return failed
    end
  end

  class Config
    def initialize(project)
      @project = project
    end

    attr_writer :fail_on_error
    def fail_on_error
      @fail_on_error ||= true
    end

    attr_writer :verbose
    def verbose
      @verbose ||= false
    end

    def max_allowed_cvss=(score)
      if score.to_f > 10.0 || score.to_f < 0
        fail("CVSS score must be between 0 and 10.0")
      else
        @max_allowed_cvss = score
      end
    end

    def max_allowed_cvss
      @max_allowed_cvss ||= 6.0
    end

    def report_output
      @report_output ||= @project.path_to(:target)
    end

    def enabled?
      !@project.packages.empty?
    end
  end

  module ProjectExtension
    include Extension

    def dependency_check
      @dependency_check ||= DependencyCheck::Config.new(project)
    end

    first_time do
      desc "Check for open CVEs on dependencies"
      Project.local_task('dependency:check')
    end

    before_define do |project|
      project.recursive_task('dependency:check')
    end

    after_define do |project|
      dependency_check = project.dependency_check

      failures = []
      if dependency_check.enabled?
        task('run_dependency_check') do |task|
          DependencyCheck.check(project, dependency_check)
          report_file = File.join(dependency_check.report_output, 'dependency-check-report.xml')
          if DependencyCheck.build_failed?(report_file, dependency_check, project)
            failures << project.name
          end
        end

        #TODO Figure out a way to have dependency:check only fail after running the task
        #on all projects.  Probably need to mimic the Liquibase architecture.
        project.task('dependency:check' => 'run_dependency_check').enhance do |task|
          unless failures.empty?
            fail("Found unacceptable vulnerabilities in #{failures.join(',')}")
          end
        end
      end

    end
  end

  class Buildr::Project
    include DependencyCheck::ProjectExtension
  end
end

